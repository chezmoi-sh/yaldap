package auth

import (
	"context"
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
	sessions := NewSessions(context.Background(), time.Millisecond)

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
			sessions := NewSessions(context.Background(), time.Millisecond)

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

func TestSessions_Delete(t *testing.T) {
	sessions := NewSessions(context.Background(), time.Millisecond)
	_ = sessions.NewSession(0, &mockLDAPObject{})

	t.Run("DeleteExistingSession", func(t *testing.T) {
		sessions.Delete(0)

		_, exists := sessions.reg.Load(0)
		assert.False(t, exists)
	})

	t.Run("DeleteNonExistingSession", func(t *testing.T) {
		sessions.Delete(1)

		_, exists := sessions.reg.Load(1)
		assert.False(t, exists)
	})
}

func TestSessions_GC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sessions := NewSessions(ctx, time.Millisecond)

	_ = sessions.NewSession(0, &mockLDAPObject{})
	t.Run("GCNonExpiredSession", func(t *testing.T) {
		sessions.GC()

		_, exists := sessions.reg.Load(0)
		assert.True(t, exists)
	})

	t.Run("GCExpiredSession", func(t *testing.T) {
		assert.Eventually(t, func() bool {
			sessions.GC()

			_, exists := sessions.reg.Load(0)
			return !exists
		}, time.Millisecond*5, time.Millisecond)
	})

	_ = sessions.NewSession(1, &mockLDAPObject{})
	t.Run("GCGoroutine", func(t *testing.T) {
		assert.Eventually(t, func() bool {
			_, exists := sessions.reg.Load(1)
			return !exists
		}, time.Millisecond*5, time.Millisecond)
	})
}

func TestSession_Session(t *testing.T) {
	sessions := NewSessions(context.Background(), time.Millisecond)
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

	_ = sessions.NewSession(1, &mockLDAPObject{})
	t.Run("GetExpiredSession", func(t *testing.T) {
		assert.Eventually(t, func() bool {
			session := sessions.Session(1)
			return assert.Nil(t, session)
		}, time.Millisecond*5, time.Millisecond)
	})

	_ = sessions.NewSession(2, &mockLDAPObject{})
	_ = sessions.NewSession(3, &mockLDAPObject{}, WithRefreshable())
	t.Run("GetRefreshableSession", func(t *testing.T) {
		session, exists := sessions.reg.Load(2)
		require.True(t, exists)

		before := session.expireAt
		sessions.Session(2)
		after := session.expireAt
		assert.False(t, after.After(before))

		session, exists = sessions.reg.Load(3)
		require.True(t, exists)

		before = session.expireAt
		sessions.Session(3)
		after = session.expireAt
		assert.True(t, after.After(before))
	})
}

func TestSessions_Session_race(t *testing.T) {
	sessions := NewSessions(context.Background(), time.Millisecond)
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
	sessions := NewSessions(context.Background(), time.Millisecond)

	_ = sessions.NewSession(0, &mockLDAPObject{})
	session, exists := sessions.reg.Load(0)

	require.True(t, exists)
	require.False(t, session.refreshable)

	_ = sessions.NewSession(1, &mockLDAPObject{}, WithRefreshable())
	session, exists = sessions.reg.Load(1)

	require.True(t, exists)
	require.True(t, session.refreshable)
}
