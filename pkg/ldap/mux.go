package ldap

import (
	"github.com/jimlambrt/gldap"
)

// server is a ldap server that uses a Directory to accept and perform search.
type server struct {
	authn     authnConns
	directory Directory
}

// NewMux creates a new LDAP server.
func NewMux(directory Directory) *gldap.Mux {
	server := &server{directory: directory}
	mux, _ := gldap.NewMux()

	_ = mux.Bind(server.bind)
	_ = mux.Search(server.search)

	withApplicationCode := func(applicationCode int) gldap.HandlerFunc {
		return func(w *gldap.ResponseWriter, req *gldap.Request) {
			resp := req.NewResponse(
				gldap.WithApplicationCode(applicationCode),
				gldap.WithResponseCode(gldap.ResultUnwillingToPerform),
				gldap.WithDiagnosticMessage("yaLDAP only support Bind and Search operation"),
			)
			_ = w.Write(resp)
		}
	}
	_ = mux.Add(withApplicationCode(gldap.ApplicationAddResponse))
	_ = mux.Modify(withApplicationCode(gldap.ApplicationModifyResponse))
	_ = mux.Delete(withApplicationCode(gldap.ApplicationDelResponse))

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

	// TODO: add password & right management
	obj := s.directory.BaseDN(msg.UserName)
	if obj.Invalid() {
		resp.SetResultCode(gldap.ResultInvalidCredentials)
		return
	}

	bindable := obj.Bind(string(msg.Password))
	if bindable.IsNone() {
		resp.SetResultCode(gldap.ResultAuthUnknown)
		return
	} else if !bindable.IsSome() {
		resp.SetResultCode(gldap.ResultInvalidCredentials)
		return
	}

	err = s.authn.addAuthn(req.ConnectionID(), obj)
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
		panic(err)
	}

	obj := s.authn.getAuthn(req.ConnectionID())
	if obj == nil {
		resp.SetResultCode(gldap.ResultAuthorizationDenied)
		return
	}

	if obj.CanSearchOn(msg.BaseDN) {
		resp.SetResultCode(gldap.ResultAuthorizationDenied)
		return
	}

	entries, err := s.directory.BaseDN(msg.BaseDN).Search(msg.Scope, msg.Filter)
	if err != nil {
		resp.SetResultCode(gldap.ResultOperationsError)
		resp.SetDiagnosticMessage(err.Error())
		return
	}

	for _, entry := range entries {
		entry := req.NewSearchResponseEntry(
			entry.DN(),
			gldap.WithAttributes(entry.Attributes().ToMap()),
		)
		_ = w.Write(entry)
	}
	resp.SetResultCode(gldap.ResultSuccess)
}
