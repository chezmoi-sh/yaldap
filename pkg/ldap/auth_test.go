package ldap

import (
	"sync"
	"testing"
	"time"

	"github.com/jimlambrt/gldap"
	"github.com/moznion/go-optional"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLdapObject map[string]Attribute

func (o mockLdapObject) DN() string             { return "" }
func (o mockLdapObject) Attributes() Attributes { return Attributes(o) }
func (o mockLdapObject) Invalid() bool          { return false }
func (o mockLdapObject) Attribute(name string) (Attribute, bool) {
	return Attributes(o).Attribute(name)
}
func (o mockLdapObject) Search(gldap.Scope, string) ([]Object, error) { return nil, nil }
func (o mockLdapObject) Bind(string) optional.Option[bool]            { return optional.None[bool]() }
func (o mockLdapObject) CanAccessTo(string) bool                      { return true }

func Test_authConns_addAuthn(t *testing.T) {
	conns := authnConns{}

	t.Run("AddConn", func(t *testing.T) {
		obj := &mockLdapObject{}

		err := conns.addAuthn(0, obj)
		require.NoError(t, err)

		conn, exists := conns.reg.Load(0)
		require.True(t, exists)
		assert.Equal(t, obj, conn.(*authnConn).obj)
	})

	t.Run("AddAlreadyExistingConn", func(t *testing.T) {
		err := conns.addAuthn(0, &mockLdapObject{})
		assert.Error(t, err)
	})

	_ = conns.addAuthn(1, &mockLdapObject{}, authnTTL(0))
	t.Run("AddAlreadyExistingButExpiredConn", func(t *testing.T) {
		err := conns.addAuthn(1, &mockLdapObject{})
		assert.NoError(t, err)
	})
}

func Test_authnConns_addAuthn_race(t *testing.T) {
	tests := []struct {
		name   string
		objs   [][]Object
		result map[string]string
	}{
		{name: "SingleAddConn",
			objs: [][]Object{{&mockLdapObject{}}}},
		{name: "MultipleAddConn",
			objs: [][]Object{{&mockLdapObject{}, &mockLdapObject{}, &mockLdapObject{}}}},
		{name: "ParallelAddConn",
			objs: [][]Object{
				{&mockLdapObject{}, &mockLdapObject{}, &mockLdapObject{}},
				{&mockLdapObject{}, &mockLdapObject{}, &mockLdapObject{}},
			}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conns := authnConns{}

			wg := sync.WaitGroup{}
			for i, objs := range tt.objs {
				wg.Add(1)
				go func(i int, objs []Object) {
					defer wg.Done()

					for ii, obj := range objs {
						id := i*10 + ii

						err := conns.addAuthn(id, obj)
						require.NoError(t, err)
					}
				}(i, objs)
			}
			wg.Wait()
		})
	}
}

func Test_authnConns_getAuthn(t *testing.T) {
	conns := authnConns{}
	obj := &mockLdapObject{}
	_ = conns.addAuthn(0, obj)

	t.Run("GetExistingConn", func(t *testing.T) {
		cobj := conns.getAuthn(0)
		require.NotNil(t, cobj)

		assert.Equal(t, obj, cobj)
	})

	t.Run("GetNonExistingConn", func(t *testing.T) {
		obj := conns.getAuthn(1)
		assert.Nil(t, obj)
	})

	_ = conns.addAuthn(1, &mockLdapObject{}, authnTTL(0))
	t.Run("GetExpiredObject", func(t *testing.T) {
		obj := conns.getAuthn(1)
		assert.Nil(t, obj)
	})

	_ = conns.addAuthn(2, &mockLdapObject{}, authnRefreshable())
	t.Run("GetRefreshableObject", func(t *testing.T) {
		conn, exists := conns.reg.Load(0)
		require.True(t, exists)

		before := conn.(*authnConn).expireAt
		conns.getAuthn(0)
		after := conn.(*authnConn).expireAt
		assert.False(t, after.After(before))

		conn, exists = conns.reg.Load(2)
		require.True(t, exists)

		before = conn.(*authnConn).expireAt
		conns.getAuthn(2)
		after = conn.(*authnConn).expireAt
		assert.True(t, after.After(before))
	})
}

func Test_authnConns_getAuthn_race(t *testing.T) {
	conns := authnConns{}
	for i := 0; i < 5; i++ {
		_ = conns.addAuthn(i, &mockLdapObject{})
	}

	tests := []struct {
		name string
		ids  [][]int
	}{
		{name: "SimpleGet",
			ids: [][]int{{0, 1, 2, 3, 4}}},
		{name: "ParallelGet",
			ids: [][]int{{0, 1}, {2, 3, 4}}},
		{name: "ConcurrentGet",
			ids: [][]int{{0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wg := sync.WaitGroup{}
			for _, ids := range tt.ids {
				wg.Add(1)
				go func(ids []int) {
					for _, id := range ids {
						conn := conns.getAuthn(id)
						assert.NotNil(t, conn)
					}
				}(ids)
			}
		})
	}
}

func Test_authnRefreshable(t *testing.T) {
	conns := authnConns{}

	_ = conns.addAuthn(0, &mockLdapObject{})
	conn, exists := conns.reg.Load(0)

	require.True(t, exists)
	require.False(t, conn.(*authnConn).refreshable)

	_ = conns.addAuthn(1, &mockLdapObject{}, authnRefreshable())
	conn, exists = conns.reg.Load(1)

	require.True(t, exists)
	require.True(t, conn.(*authnConn).refreshable)
}

func Test_authnTTL(t *testing.T) {
	conns := authnConns{}

	_ = conns.addAuthn(0, &mockLdapObject{})
	conn, exists := conns.reg.Load(0)

	require.True(t, exists)
	require.Equal(t, defaultTTL, conn.(*authnConn).ttl)

	_ = conns.addAuthn(1, &mockLdapObject{}, authnTTL(60*time.Second))
	conn, exists = conns.reg.Load(1)

	require.True(t, exists)
	require.Equal(t, 60*time.Second, conn.(*authnConn).ttl)
}
