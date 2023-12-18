package auth

import (
	"fmt"
	"time"

	xsync "github.com/puzpuzpuz/xsync/v3"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
)

type (
	// Sessions register all LDAP authenticated connections that are
	// allowed to perform operations.
	Sessions struct {
		reg *xsync.MapOf[int, *Session]
	}

	// Session represents a single LDAP authenticated connection.
	Session struct {
		refreshable bool
		ttl         time.Duration

		expireAt time.Time
		obj      ldap.Object
	}

	// SessionOption customize a authnConn before its registration on authConns.
	SessionOption func(conn *Session)

	// Error represents an error that occurs during the authentication.
	Error struct{ error }
)

const defaultTTL = 5 * time.Minute

// NewSessions returns a new AuthnConns instance.
func NewSessions() *Sessions {
	return &Sessions{
		reg: xsync.NewMapOf[int, *Session](),
	}
}

// NewSession adds the given LDAP object the list of authenticated connections.
func (sessions *Sessions) NewSession(id int, obj ldap.Object, opts ...SessionOption) error {
	session := &Session{ttl: defaultTTL, obj: obj}
	for _, opt := range opts {
		opt(session)
	}

	session.expireAt = time.Now().Add(session.ttl)

	eobj := sessions.Session(id)
	if eobj != nil {
		return &Error{fmt.Errorf("connection already authenticated")}
	}

	sessions.reg.Store(id, session)
	return nil
}

// Session returns the LDAP object if it is authenticated. Otherwise, if the
// connection ID doesn't exist or as expired, it returns nil.
// Furthermore, if the connection is expired, it is automatically removed
// from the connections list.
func (sessions *Sessions) Session(id int) *Session {
	session, exists := sessions.reg.Load(id)

	switch {
	case !exists:
		return nil
	case session.expireAt.Before(time.Now()):
		sessions.reg.Delete(id)
		return nil
	case session.refreshable:
		session.expireAt = time.Now().Add(session.ttl)
	}

	return session
}

// Object returns the LDAP object associated with the given session.
func (session Session) Object() ldap.Object {
	return session.obj
}

// AuthnRefreshable allows the given conn to have its expiration date increased
// after each operation.
func AuthnRefreshable() SessionOption {
	return func(session *Session) { session.refreshable = true }
}

// AuthnTTL customizes the given conn TTL.
func AuthnTTL(ttl time.Duration) SessionOption {
	return func(session *Session) { session.ttl = ttl }
}
