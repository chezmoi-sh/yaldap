package ldap

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/jimlambrt/gldap"
	"github.com/xunleii/yaldap/internal/ldap/auth"
	"github.com/xunleii/yaldap/pkg/ldap/directory"
	"github.com/xunleii/yaldap/pkg/utils"
	"golang.org/x/exp/slices"
)

// server is a ldap server that uses a Directory to accept and perform search.
type server struct {
	sessions  *auth.Sessions
	directory directory.Directory

	logger *slog.Logger
}

// NewMux creates a new LDAP server.
func NewMux(logger *slog.Logger, directory directory.Directory, sessions *auth.Sessions) *gldap.Mux {
	server := &server{
		logger:    logger,
		sessions:  sessions,
		directory: directory,
	}
	mux, _ := gldap.NewMux()

	_ = mux.Bind(server.bind)
	_ = mux.Unbind(server.unbind)
	_ = mux.Search(server.search)
	_ = mux.Add(server.add)
	_ = mux.Modify(server.modify)
	_ = mux.Delete(server.del)

	return mux
}

// bind implements the LDAP bind mechanism to authenticate someone to perform a search.
func (s *server) bind(w *gldap.ResponseWriter, req *gldap.Request) {
	log := s.logger.With(
		slog.String("method", "bind"),
		slog.Group("session",
			slog.Int("id", req.ConnectionID()),
			slog.Int("request_id", req.ID),
		),
	)

	resp := req.NewBindResponse()
	defer func() { _ = w.Write(resp) }()

	msg, err := req.GetSimpleBindMessage()
	if err != nil {
		log.Error("unable to get simple bind message", slog.String("error", err.Error()))
		resp.SetResultCode(gldap.ResultLocalError)
		resp.SetDiagnosticMessage(err.Error())
		return
	}

	obj := s.directory.BaseDN(msg.UserName)
	if obj == nil {
		log.Error("unable to find username", slog.String("username", msg.UserName))
		resp.SetResultCode(gldap.ResultInvalidCredentials)
		// NOTE: we don't want to give any information about the user existence
		//       in order to avoid any bruteforce attack.
		return
	}

	if !obj.Bind(string(msg.Password)) {
		log.Error("unable to bind user", slog.String("username", msg.UserName))
		resp.SetResultCode(gldap.ResultInvalidCredentials)
		// NOTE: we don't want to give any information about the user existence
		//       in order to avoid any bruteforce attack.
		return
	}
	log = log.With(slog.String("bind_dn", obj.DN()))

	err = s.sessions.NewSession(req.ConnectionID(), obj)
	if err != nil {
		log.Error("unable to create session", slog.String("error", err.Error()))
		resp.SetResultCode(gldap.ResultLocalError)
		resp.SetDiagnosticMessage(err.Error())
		return
	}

	log.Info("bind successful")
	resp.SetResultCode(gldap.ResultSuccess)
}

func (s *server) unbind(_ *gldap.ResponseWriter, req *gldap.Request) {
	log := s.logger.With(
		slog.String("method", "unbind"),
		slog.Group("session",
			slog.Int("id", req.ConnectionID()),
			slog.Int("request_id", req.ID),
		),
	)

	session := s.sessions.Session(req.ConnectionID())
	if session == nil {
		return
	}
	log = log.With(slog.String("bind_dn", session.Object().DN()))

	s.sessions.Delete(req.ConnectionID())
	log.Info("unbind successful")
}

// Search implements the LDAP search mechanism.
func (s *server) search(w *gldap.ResponseWriter, req *gldap.Request) {
	log := s.logger.With(
		slog.String("method", "search"),
		slog.Group("session",
			slog.Int("id", req.ConnectionID()),
			slog.Int("request_id", req.ID),
		),
	)

	resp := req.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultNoSuchObject))
	defer func() { _ = w.Write(resp) }()

	msg, err := req.GetSearchMessage()
	if err != nil {
		log.Error("unable to get search message", slog.String("error", err.Error()))
		resp.SetResultCode(gldap.ResultParamError)
		resp.SetDiagnosticMessage(err.Error())
		return
	}
	log = log.With(slog.Group("request",
		slog.String("base_dn", msg.BaseDN),
		slog.String("filter", msg.Filter),
		slog.String("scope", utils.LDAPScopes[msg.Scope]),
		slog.Any("attributes", msg.Attributes),
	))

	session := s.sessions.Session(req.ConnectionID())
	if session == nil {
		log.Error("session not found or expired")
		resp.SetResultCode(gldap.ResultAuthorizationDenied)
		return
	}
	obj := session.Object()
	log = log.With(slog.String("bind_dn", obj.DN()))

	baseDn := s.directory.BaseDN(msg.BaseDN)
	if baseDn == nil {
		log.Error("unable to find base DN")
		resp.SetResultCode(gldap.ResultNoSuchObject)
		return
	}

	entries, err := baseDn.Search(msg.Scope, msg.Filter)
	if err != nil {
		log.Error("unable to search", slog.String("error", err.Error()))
		resp.SetResultCode(gldap.ResultOperationsError)
		resp.SetDiagnosticMessage(err.Error())
		return
	}

	var count int
	for _, entry := range entries {
		if obj.CanSearchOn(entry.DN()) {
			resp := req.NewSearchResponseEntry(entry.DN())
			attrs := entry.Attributes()

			// Filter attributes if needed
			for attr, values := range attrs {
				if len(msg.Attributes) == 0 || slices.ContainsFunc(
					msg.Attributes,
					func(s string) bool { return strings.EqualFold(s, attr) },
				) {
					resp.AddAttribute(attr, values)
				}
			}

			_ = w.Write(resp)
			count++
		}
	}
	log.Info(fmt.Sprintf("found %d entries", count))
	resp.SetResultCode(gldap.ResultSuccess)
}

// add implements the LDAP add mechanism.
func (s *server) add(w *gldap.ResponseWriter, req *gldap.Request) {
	log := s.logger.With(
		slog.String("method", "add"),
		slog.Group("session",
			slog.Int("id", req.ConnectionID()),
			slog.Int("request_id", req.ID),
		),
	)
	log.Warn("operation is not supported")

	resp := req.NewResponse(
		gldap.WithApplicationCode(gldap.ApplicationAddResponse),
		gldap.WithResponseCode(gldap.ResultUnwillingToPerform),
		gldap.WithDiagnosticMessage("yaLDAP only support Bind and Search operations"),
	)
	_ = w.Write(resp)
}

// modify implements the LDAP modify mechanism.
func (s *server) modify(w *gldap.ResponseWriter, req *gldap.Request) {
	log := s.logger.With(
		slog.String("method", "modify"),
		slog.Group("session",
			slog.Int("id", req.ConnectionID()),
			slog.Int("request_id", req.ID),
		),
	)
	log.Warn("operation is not supported")

	resp := req.NewResponse(
		gldap.WithApplicationCode(gldap.ApplicationModifyResponse),
		gldap.WithResponseCode(gldap.ResultUnwillingToPerform),
		gldap.WithDiagnosticMessage("yaLDAP only support Bind and Search operations"),
	)
	_ = w.Write(resp)
}

// del implements the LDAP delete mechanism.
func (s *server) del(w *gldap.ResponseWriter, req *gldap.Request) {
	log := s.logger.With(
		slog.String("method", "del"),
		slog.Group("session",
			slog.Int("id", req.ConnectionID()),
			slog.Int("request_id", req.ID),
		),
	)
	log.Warn("operation is not supported")

	resp := req.NewResponse(
		gldap.WithApplicationCode(gldap.ApplicationDelResponse),
		gldap.WithResponseCode(gldap.ResultUnwillingToPerform),
		gldap.WithDiagnosticMessage("yaLDAP only support Bind and Search operations"),
	)
	_ = w.Write(resp)
}
