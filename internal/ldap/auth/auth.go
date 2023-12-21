package auth

import (
	"context"
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
		ttl time.Duration
	}

	// Session represents a single LDAP authenticated connection.
	Session struct {
		refreshable bool

		expireAt time.Time
		obj      ldap.Object
	}

	// SessionOption customize a authnConn before its registration on authConns.
	SessionOption func(conn *Session)

	// Error represents an error that occurs during the authentication.
	Error struct{ error }
)

// NewSessions returns a new AuthnConns instance.
func NewSessions(ctx context.Context, ttl time.Duration) *Sessions {
	sessions := &Sessions{
		reg: xsync.NewMapOf[int, *Session](),
		ttl: ttl,
	}

	// Run the GC every TTL/2
	go func() {
		ticker := time.NewTicker(ttl / 2)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sessions.GC()
			}
		}
	}()

	return sessions
}

// NewSession adds the given LDAP object the list of authenticated connections.
func (sessions *Sessions) NewSession(id int, obj ldap.Object, opts ...SessionOption) error {
	session := &Session{obj: obj}
	for _, opt := range opts {
		opt(session)
	}

	session.expireAt = time.Now().Add(sessions.ttl)

	eobj := sessions.Session(id)
	if eobj != nil {
		return &Error{fmt.Errorf("connection already authenticated")}
	}

	sessions.reg.Store(id, session)
	return nil
}

// Delete removes the given connection ID from the list of authenticated
// connections.
func (sessions *Sessions) Delete(id int) { sessions.reg.Delete(id) }

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
		session.expireAt = time.Now().Add(sessions.ttl)
	}

	return session
}

// GC removes all expired connections from the list of authenticated.
func (sessions Sessions) GC() {
	sessions.reg.Range(func(key int, value *Session) bool {
		if value.expireAt.Before(time.Now()) {
			sessions.reg.Delete(key)
		}
		return true
	})
}

// Object returns the LDAP object associated with the given session.
func (session Session) Object() ldap.Object {
	return session.obj
}

// WithRefreshable allows the given conn to have its expiration date increased
// after each operation.
func WithRefreshable() SessionOption {
	return func(session *Session) { session.refreshable = true }
}
