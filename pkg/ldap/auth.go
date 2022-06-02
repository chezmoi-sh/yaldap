package ldap

import (
	"fmt"
	"sync"
	"time"
)

type (
	// authnConns register all LDAP authenticated connections that are
	// allowed to perform operations.
	authnConns struct {
		reg sync.Map
	}

	// authnConn represents a single LDAP authenticated connection.
	authnConn struct {
		refreshable bool
		ttl         time.Duration

		expireAt time.Time
		obj      Object
	}

	// authnConnOption customize a authnConn before its registration on authConns.
	authnConnOption func(conn *authnConn)

	authnError struct{ error }
)

const defaultTTL = 5 * time.Minute

var authnIdAlreadyExists = &authnError{fmt.Errorf("connection already authenticated")}

// addAuthn adds the given LDAP object the list of authenticated connections.
func (conns *authnConns) addAuthn(id int, obj Object, opts ...authnConnOption) error {
	conn := &authnConn{ttl: defaultTTL, obj: obj}
	for _, opt := range opts {
		opt(conn)
	}

	conn.expireAt = time.Now().Add(conn.ttl)

	eobj := conns.getAuthn(id)
	if eobj != nil {
		return authnIdAlreadyExists
	}

	conns.reg.Store(id, conn)
	return nil
}

// getAuthn returns the LDAP object if it is authenticated. Otherwise, if the
// connection ID doesn't exist or as expired, it returns nil.
// Furthermore, if the connection is expired, it is automatically removed
// from the connections list.
func (conns *authnConns) getAuthn(id int) Object {
	conn, exists := conns.reg.Load(id)

	switch {
	case !exists:
		return nil
	case conn.(*authnConn).expireAt.Before(time.Now()):
		conns.reg.Delete(id)
		return nil
	case conn.(*authnConn).refreshable:
		conn.(*authnConn).expireAt = time.Now().Add(conn.(*authnConn).ttl)
	}

	return conn.(*authnConn).obj
}

// authnRefreshable allows the given conn to have its expiration date increased
// after each operation.
func authnRefreshable() authnConnOption {
	return func(conn *authnConn) { conn.refreshable = true }
}

// authnTTL customizes the given conn TTL.
func authnTTL(ttl time.Duration) authnConnOption {
	return func(conn *authnConn) { conn.ttl = ttl }
}
