package auth

import (
	"fmt"
	"time"

	"github.com/puzpuzpuz/xsync"

	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
)

type (
	// AuthnConns register all LDAP authenticated connections that are
	// allowed to perform operations.
	AuthnConns struct {
		reg *xsync.MapOf[int, *AuthnConn]
	}

	// AuthnConn represents a single LDAP authenticated connection.
	AuthnConn struct {
		refreshable bool
		ttl         time.Duration

		expireAt time.Time
		obj      ldap.Object
	}

	// AuthnConnOption customize a authnConn before its registration on authConns.
	AuthnConnOption func(conn *AuthnConn)

	// AuthnError represents an error that occurs during the authentication.
	AuthnError struct{ error }
)

const defaultTTL = 5 * time.Minute

// NewAuthnConns returns a new AuthnConns instance.
func NewAuthnConns() *AuthnConns {
	return &AuthnConns{
		reg: xsync.NewIntegerMapOf[int, *AuthnConn](),
	}
}

// AddAuthn adds the given LDAP object the list of authenticated connections.
func (conns *AuthnConns) AddAuthn(id int, obj ldap.Object, opts ...AuthnConnOption) error {
	conn := &AuthnConn{ttl: defaultTTL, obj: obj}
	for _, opt := range opts {
		opt(conn)
	}

	conn.expireAt = time.Now().Add(conn.ttl)

	eobj := conns.GetAuthn(id)
	if eobj != nil {
		return &AuthnError{fmt.Errorf("connection already authenticated")}
	}

	conns.reg.Store(id, conn)
	return nil
}

// GetAuthn returns the LDAP object if it is authenticated. Otherwise, if the
// connection ID doesn't exist or as expired, it returns nil.
// Furthermore, if the connection is expired, it is automatically removed
// from the connections list.
func (conns *AuthnConns) GetAuthn(id int) ldap.Object {
	conn, exists := conns.reg.Load(id)

	switch {
	case !exists:
		return nil
	case conn.expireAt.Before(time.Now()):
		conns.reg.Delete(id)
		return nil
	case conn.refreshable:
		conn.expireAt = time.Now().Add(conn.ttl)
	}

	return conn.obj
}

// AuthnRefreshable allows the given conn to have its expiration date increased
// after each operation.
func AuthnRefreshable() AuthnConnOption {
	return func(conn *AuthnConn) { conn.refreshable = true }
}

// AuthnTTL customizes the given conn TTL.
func AuthnTTL(ttl time.Duration) AuthnConnOption {
	return func(conn *AuthnConn) { conn.ttl = ttl }
}
