package ldap

import (
	"github.com/jimlambrt/gldap"
	"github.com/xunleii/yaldap/internal/ldap/auth"
	"github.com/xunleii/yaldap/pkg/ldap/directory"
)

// server is a ldap server that uses a Directory to accept and perform search.
type server struct {
	sessions  *auth.Sessions
	directory directory.Directory
}

// NewMux creates a new LDAP server.
func NewMux(directory directory.Directory) *gldap.Mux {
	server := &server{sessions: auth.NewSessions(), directory: directory}
	mux, _ := gldap.NewMux()

	_ = mux.Bind(server.bind)
	_ = mux.Search(server.search)
	_ = mux.Add(server.add)
	_ = mux.Modify(server.modify)
	_ = mux.Delete(server.del)

	return mux
}

// bind implements the LDAP bind mechanism to authenticate someone to perform a search.
func (s *server) bind(w *gldap.ResponseWriter, req *gldap.Request) {
	resp := req.NewBindResponse()
	defer func() { _ = w.Write(resp) }()

	msg, err := req.GetSimpleBindMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultLocalError)
		resp.SetDiagnosticMessage(err.Error())
		return
	}

	obj := s.directory.BaseDN(msg.UserName)
	if obj == nil {
		resp.SetResultCode(gldap.ResultInvalidCredentials)
		// NOTE: we don't want to give any information about the user existence
		//       in order to avoid any bruteforce attack.
		return
	}

	if !obj.Bind(string(msg.Password)) {
		resp.SetResultCode(gldap.ResultInvalidCredentials)
		// NOTE: we don't want to give any information about the user existence
		//       in order to avoid any bruteforce attack.
		return
	}

	err = s.sessions.NewSession(req.ConnectionID(), obj)
	if err != nil {
		resp.SetResultCode(gldap.ResultLocalError)
		resp.SetDiagnosticMessage(err.Error())
		return
	}
	resp.SetResultCode(gldap.ResultSuccess)
}

// Search implements the LDAP search mechanism.
func (s *server) search(w *gldap.ResponseWriter, req *gldap.Request) {
	resp := req.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultNoSuchObject))
	defer func() { _ = w.Write(resp) }()

	msg, err := req.GetSearchMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultParamError)
		resp.SetDiagnosticMessage(err.Error())
		return
	}

	session := s.sessions.Session(req.ConnectionID())
	if session == nil {
		resp.SetResultCode(gldap.ResultAuthorizationDenied)
		return
	}
	obj := session.Object()

	baseDn := s.directory.BaseDN(msg.BaseDN)
	if baseDn == nil {
		resp.SetResultCode(gldap.ResultNoSuchObject)
		return
	}

	entries, err := baseDn.Search(msg.Scope, msg.Filter)
	if err != nil {
		resp.SetResultCode(gldap.ResultOperationsError)
		resp.SetDiagnosticMessage(err.Error())
		return
	}

	for _, entry := range entries {
		if obj.CanSearchOn(entry.DN()) {
			entry := req.NewSearchResponseEntry(
				entry.DN(),
				gldap.WithAttributes(entry.Attributes()),
			)
			_ = w.Write(entry)
		}
	}
	resp.SetResultCode(gldap.ResultSuccess)
}

// add implements the LDAP add mechanism.
func (s *server) add(w *gldap.ResponseWriter, req *gldap.Request) {
	resp := req.NewResponse(
		gldap.WithApplicationCode(gldap.ApplicationAddResponse),
		gldap.WithResponseCode(gldap.ResultUnwillingToPerform),
		gldap.WithDiagnosticMessage("yaLDAP only support Bind and Search operations"),
	)
	_ = w.Write(resp)
}

// modify implements the LDAP modify mechanism.
func (s *server) modify(w *gldap.ResponseWriter, req *gldap.Request) {
	resp := req.NewResponse(
		gldap.WithApplicationCode(gldap.ApplicationModifyResponse),
		gldap.WithResponseCode(gldap.ResultUnwillingToPerform),
		gldap.WithDiagnosticMessage("yaLDAP only support Bind and Search operations"),
	)
	_ = w.Write(resp)
}

// del implements the LDAP delete mechanism.
func (s *server) del(w *gldap.ResponseWriter, req *gldap.Request) {
	resp := req.NewResponse(
		gldap.WithApplicationCode(gldap.ApplicationDelResponse),
		gldap.WithResponseCode(gldap.ResultUnwillingToPerform),
		gldap.WithDiagnosticMessage("yaLDAP only support Bind and Search operations"),
	)
	_ = w.Write(resp)
}
