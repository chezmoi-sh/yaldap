package auth

import (
	"sync"
	"testing"
	"time"

	"github.com/jimlambrt/gldap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
)

type mockLDAPObject map[string][]string

func (o mockLDAPObject) DN() string                                        { return "" }
func (o mockLDAPObject) Attributes() ldap.Attributes                       { return ldap.Attributes(o) }
func (o mockLDAPObject) Search(gldap.Scope, string) ([]ldap.Object, error) { return nil, nil }
func (o mockLDAPObject) Bind(string) bool                                  { return false }
func (o mockLDAPObject) CanSearchOn(string) bool                           { return true }

func TestSessions_NewSession(t *testing.T) {
	sessions := NewSessions()

	t.Run("AddSession", func(t *testing.T) {
		obj := &mockLDAPObject{}

		err := sessions.NewSession(0, obj)
		require.NoError(t, err)

		session, exists := sessions.reg.Load(0)
		require.True(t, exists)
		assert.Equal(t, obj, session.obj)
	})

	t.Run("AddAlreadyExistingSession", func(t *testing.T) {
		err := sessions.NewSession(0, &mockLDAPObject{})
		assert.Error(t, err)
	})

	_ = sessions.NewSession(1, &mockLDAPObject{}, AuthnTTL(0))
	t.Run("AddAlreadyExistingButExpiredSession", func(t *testing.T) {
		err := sessions.NewSession(1, &mockLDAPObject{})
		assert.NoError(t, err)
	})
}

func TestSessions_NewSession_race(t *testing.T) {
	tests := []struct {
		name   string
		objs   [][]ldap.Object
		result map[string]string
	}{
		{
			name: "SingleAddSession",
			objs: [][]ldap.Object{{&mockLDAPObject{}}},
		},
		{
			name: "MultipleAddSession",
			objs: [][]ldap.Object{{&mockLDAPObject{}, &mockLDAPObject{}, &mockLDAPObject{}}},
		},
		{
			name: "ParallelAddSession",
			objs: [][]ldap.Object{
				{&mockLDAPObject{}, &mockLDAPObject{}, &mockLDAPObject{}},
				{&mockLDAPObject{}, &mockLDAPObject{}, &mockLDAPObject{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions := NewSessions()

			wg := sync.WaitGroup{}
			for i, objs := range tt.objs {
				wg.Add(1)
				go func(i int, objs []ldap.Object) {
					defer wg.Done()

					for ii, obj := range objs {
						id := i*10 + ii

						err := sessions.NewSession(id, obj)
						require.NoError(t, err)
					}
				}(i, objs)
			}
			wg.Wait()
		})
	}
}

func TestSession_Session(t *testing.T) {
	sessions := NewSessions()
	obj := &mockLDAPObject{}
	_ = sessions.NewSession(0, obj)

	t.Run("GetExistingSession", func(t *testing.T) {
		session := sessions.Session(0)
		require.NotNil(t, session)

		assert.Equal(t, obj, session.Object())
	})

	t.Run("GetNonExistingSession", func(t *testing.T) {
		session := sessions.Session(1)
		assert.Nil(t, session)
	})

	_ = sessions.NewSession(1, &mockLDAPObject{}, AuthnTTL(0))
	t.Run("GetExpiredSession", func(t *testing.T) {
		session := sessions.Session(1)
		assert.Nil(t, session)
	})

	_ = sessions.NewSession(2, &mockLDAPObject{}, AuthnRefreshable())
	t.Run("GetRefreshableSession", func(t *testing.T) {
		session, exists := sessions.reg.Load(0)
		require.True(t, exists)

		before := session.expireAt
		sessions.Session(0)
		after := session.expireAt
		assert.False(t, after.After(before))

		session, exists = sessions.reg.Load(2)
		require.True(t, exists)

		before = session.expireAt
		sessions.Session(2)
		after = session.expireAt
		assert.True(t, after.After(before))
	})
}

func TestSessions_Session_race(t *testing.T) {
	sessions := NewSessions()
	for i := 0; i < 5; i++ {
		_ = sessions.NewSession(i, &mockLDAPObject{})
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
						session := sessions.Session(id)
						assert.NotNil(t, session)
					}
				}(ids)
			}
		})
	}
}

func TestSessionRefreshable(t *testing.T) {
	sessions := NewSessions()

	_ = sessions.NewSession(0, &mockLDAPObject{})
	session, exists := sessions.reg.Load(0)

	require.True(t, exists)
	require.False(t, session.refreshable)

	_ = sessions.NewSession(1, &mockLDAPObject{}, AuthnRefreshable())
	session, exists = sessions.reg.Load(1)

	require.True(t, exists)
	require.True(t, session.refreshable)
}

func TestSessionTTL(t *testing.T) {
	sessions := NewSessions()

	_ = sessions.NewSession(0, &mockLDAPObject{})
	session, exists := sessions.reg.Load(0)

	require.True(t, exists)
	require.Equal(t, defaultTTL, session.ttl)

	_ = sessions.NewSession(1, &mockLDAPObject{}, AuthnTTL(60*time.Second))
	session, exists = sessions.reg.Load(1)

	require.True(t, exists)
	require.Equal(t, 60*time.Second, session.ttl)
}
