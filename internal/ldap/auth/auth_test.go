package auth

import (
	"sync"
	"testing"
	"time"

	"github.com/jimlambrt/gldap"
	"github.com/moznion/go-optional"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
)

type mockLdapObject map[string]ldap.Attribute

func (o mockLdapObject) DN() string                  { return "" }
func (o mockLdapObject) Attributes() ldap.Attributes { return ldap.Attributes(o) }
func (o mockLdapObject) Invalid() bool               { return false }
func (o mockLdapObject) Attribute(name string) (ldap.Attribute, bool) {
	return ldap.Attributes(o).Attribute(name)
}
func (o mockLdapObject) Search(gldap.Scope, string) ([]ldap.Object, error) { return nil, nil }
func (o mockLdapObject) Bind(string) optional.Option[bool]                 { return optional.None[bool]() }
func (o mockLdapObject) CanAccessTo(string) bool                           { return true }

func Test_authConns_AddAuthn(t *testing.T) {
	conns := NewAuthnConns()

	t.Run("AddConn", func(t *testing.T) {
		obj := &mockLdapObject{}

		err := conns.AddAuthn(0, obj)
		require.NoError(t, err)

		conn, exists := conns.reg.Load(0)
		require.True(t, exists)
		assert.Equal(t, obj, conn.obj)
	})

	t.Run("AddAlreadyExistingConn", func(t *testing.T) {
		err := conns.AddAuthn(0, &mockLdapObject{})
		assert.Error(t, err)
	})

	_ = conns.AddAuthn(1, &mockLdapObject{}, AuthnTTL(0))
	t.Run("AddAlreadyExistingButExpiredConn", func(t *testing.T) {
		err := conns.AddAuthn(1, &mockLdapObject{})
		assert.NoError(t, err)
	})
}

func Test_authnConns_AddAuthn_race(t *testing.T) {
	tests := []struct {
		name   string
		objs   [][]ldap.Object
		result map[string]string
	}{
		{
			name: "SingleAddConn",
			objs: [][]ldap.Object{{&mockLdapObject{}}},
		},
		{
			name: "MultipleAddConn",
			objs: [][]ldap.Object{{&mockLdapObject{}, &mockLdapObject{}, &mockLdapObject{}}},
		},
		{
			name: "ParallelAddConn",
			objs: [][]ldap.Object{
				{&mockLdapObject{}, &mockLdapObject{}, &mockLdapObject{}},
				{&mockLdapObject{}, &mockLdapObject{}, &mockLdapObject{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conns := NewAuthnConns()

			wg := sync.WaitGroup{}
			for i, objs := range tt.objs {
				wg.Add(1)
				go func(i int, objs []ldap.Object) {
					defer wg.Done()

					for ii, obj := range objs {
						id := i*10 + ii

						err := conns.AddAuthn(id, obj)
						require.NoError(t, err)
					}
				}(i, objs)
			}
			wg.Wait()
		})
	}
}

func Test_authnConns_GetAuthn(t *testing.T) {
	conns := NewAuthnConns()
	obj := &mockLdapObject{}
	_ = conns.AddAuthn(0, obj)

	t.Run("GetExistingConn", func(t *testing.T) {
		cobj := conns.GetAuthn(0)
		require.NotNil(t, cobj)

		assert.Equal(t, obj, cobj)
	})

	t.Run("GetNonExistingConn", func(t *testing.T) {
		obj := conns.GetAuthn(1)
		assert.Nil(t, obj)
	})

	_ = conns.AddAuthn(1, &mockLdapObject{}, AuthnTTL(0))
	t.Run("GetExpiredObject", func(t *testing.T) {
		obj := conns.GetAuthn(1)
		assert.Nil(t, obj)
	})

	_ = conns.AddAuthn(2, &mockLdapObject{}, AuthnRefreshable())
	t.Run("GetRefreshableObject", func(t *testing.T) {
		conn, exists := conns.reg.Load(0)
		require.True(t, exists)

		before := conn.expireAt
		conns.GetAuthn(0)
		after := conn.expireAt
		assert.False(t, after.After(before))

		conn, exists = conns.reg.Load(2)
		require.True(t, exists)

		before = conn.expireAt
		conns.GetAuthn(2)
		after = conn.expireAt
		assert.True(t, after.After(before))
	})
}

func Test_authnConns_GetAuthn_race(t *testing.T) {
	conns := NewAuthnConns()
	for i := 0; i < 5; i++ {
		_ = conns.AddAuthn(i, &mockLdapObject{})
	}

	tests := []struct {
		name string
		ids  [][]int
	}{
		{
			name: "SimpleGet",
			ids:  [][]int{{0, 1, 2, 3, 4}},
		},
		{
			name: "ParallelGet",
			ids:  [][]int{{0, 1}, {2, 3, 4}},
		},
		{
			name: "ConcurrentGet",
			ids:  [][]int{{0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wg := sync.WaitGroup{}
			for _, ids := range tt.ids {
				wg.Add(1)
				go func(ids []int) {
					for _, id := range ids {
						conn := conns.GetAuthn(id)
						assert.NotNil(t, conn)
					}
				}(ids)
			}
		})
	}
}

func Test_authnRefreshable(t *testing.T) {
	conns := NewAuthnConns()

	_ = conns.AddAuthn(0, &mockLdapObject{})
	conn, exists := conns.reg.Load(0)

	require.True(t, exists)
	require.False(t, conn.refreshable)

	_ = conns.AddAuthn(1, &mockLdapObject{}, AuthnRefreshable())
	conn, exists = conns.reg.Load(1)

	require.True(t, exists)
	require.True(t, conn.refreshable)
}

func Test_authnTTL(t *testing.T) {
	conns := NewAuthnConns()

	_ = conns.AddAuthn(0, &mockLdapObject{})
	conn, exists := conns.reg.Load(0)

	require.True(t, exists)
	require.Equal(t, defaultTTL, conn.ttl)

	_ = conns.AddAuthn(1, &mockLdapObject{}, AuthnTTL(60*time.Second))
	conn, exists = conns.reg.Load(1)

	require.True(t, exists)
	require.Equal(t, 60*time.Second, conn.ttl)
}
