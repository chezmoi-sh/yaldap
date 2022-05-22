package filters_test

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

func TestAndResolver(t *testing.T) {
	tests := []struct {
		filter   string
		expected func(t assert.TestingT, value bool, msgAndArgs ...interface{}) bool
	}{
		{
			filter:   "(&(objectClass=posixAccount)(uid=alice))", // T & T
			expected: assert.True,
		},
		{
			filter:   "(&(objectClass=posixAccount)(uid=bob))", // T & F
			expected: assert.False,
		},
		{
			filter:   "(&(objectClass=inetOrgPerson)(uid=alice))", // F & T
			expected: assert.False,
		},
		{
			filter:   "(&(objectClass=inetOrgPerson)(uid=bob))", // F & F
			expected: assert.False,
		},
		{
			filter:   "(&(objectClass=posixAccount)(uid=alice)(uid=alice))", // T & T & T
			expected: assert.True,
		},
		{
			filter:   "(&(objectClass=posixAccount)(uid=alice)(uid=bob))", // T & T & F
			expected: assert.False,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			filter, err := goldap.CompileFilter(tt.filter)
			require.NoError(t, err)

			actual, err := filters.AndResolver(object, filter)
			require.NoError(t, err)
			tt.expected(t, actual)
		})
	}
}

func TestAndResolver_Error(t *testing.T) {
	t.Run("(&())", func(t *testing.T) {
		actual, err := filters.AndResolver(object, &ber.Packet{Children: []*ber.Packet{}})
		require.NoError(t, err)
		assert.False(t, actual)
	})

	t.Run("(&(objectClass=posixAccount)(ERROR))", func(t *testing.T) {
		filter := &ber.Packet{
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
					Children: []*ber.Packet{
						{Value: "objectClass"},
						{Value: "posixAccount"},
					},
				},
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
				},
			},
		}
		_, err := filters.AndResolver(object, filter)
		require.EqualError(t, err, "invalid `Equality Match` filter: should only contain the attribute & the condition")
	})

	t.Run("(&(ERROR)(uid=alice))", func(t *testing.T) {
		filter := &ber.Packet{
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
				},
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
					Children: []*ber.Packet{
						{Value: "uid"},
						{Value: "alice"},
					},
				},
			},
		}
		_, err := filters.AndResolver(object, filter)
		require.EqualError(t, err, "invalid `Equality Match` filter: should only contain the attribute & the condition")
	})

	// return-fast behavior: return false when at least one filter returns false
	// In this case, the first filter returns false, so the second filter is not
	// evaluated
	t.Run("(&(objectClass=inetOrgPerson)(ERROR))", func(t *testing.T) {
		filter := &ber.Packet{
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
					Children: []*ber.Packet{
						{Value: "objectClass"},
						{Value: "inetOrgPerson"},
					},
				},
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
				},
			},
		}
		_, err := filters.AndResolver(object, filter)
		require.NoError(t, err)
	})
}

func TestOrResolver(t *testing.T) {
	tests := []struct {
		filter   string
		expected func(t assert.TestingT, value bool, msgAndArgs ...interface{}) bool
	}{
		{
			filter:   "(|(objectClass=posixAccount)(uid=alice))", // T | T
			expected: assert.True,
		},
		{
			filter:   "(|(objectClass=posixAccount)(uid=bob))", // T | F
			expected: assert.True,
		},
		{
			filter:   "(|(objectClass=inetOrgPerson)(uid=alice))", // F | T
			expected: assert.True,
		},
		{
			filter:   "(|(objectClass=inetOrgPerson)(uid=bob))", // F | F
			expected: assert.False,
		},
		{
			filter:   "(|(objectClass=posixAccount)(uid=alice)(uid=alice))", // T | T | T
			expected: assert.True,
		},
		{
			filter:   "(|(objectClass=posixAccount)(uid=alice)(uid=bob))", // T | T | F
			expected: assert.True,
		},
		{
			filter:   "(|(objectClass=inetOrgPerson)(uid=alice)(uid=alice))", // F | T | T
			expected: assert.True,
		},
		{
			filter:   "(|(objectClass=inetOrgPerson)(uid=alice)(uid=bob))", // F | T | F
			expected: assert.True,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			filter, err := goldap.CompileFilter(tt.filter)
			require.NoError(t, err)

			actual, err := filters.OrResolver(object, filter)
			require.NoError(t, err)
			tt.expected(t, actual)
		})
	}
}

func TestOrResolver_Error(t *testing.T) {
	t.Run("(|())", func(t *testing.T) {
		actual, err := filters.OrResolver(object, &ber.Packet{Children: []*ber.Packet{}})
		require.NoError(t, err)
		assert.False(t, actual)
	})

	t.Run("(|(ERROR)(uid=alice))", func(t *testing.T) {
		filter := &ber.Packet{
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
				},
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
					Children: []*ber.Packet{
						{Value: "uid"},
						{Value: "alice"},
					},
				},
			},
		}
		_, err := filters.OrResolver(object, filter)
		require.EqualError(t, err, "invalid `Equality Match` filter: should only contain the attribute & the condition")
	})

	t.Run("(|(objectClass=inetOrgPerson)(ERROR))", func(t *testing.T) {
		filter := &ber.Packet{
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
					Children: []*ber.Packet{
						{Value: "objectClass"},
						{Value: "inetOrgPerson"},
					},
				},
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
				},
			},
		}
		_, err := filters.OrResolver(object, filter)
		require.EqualError(t, err, "invalid `Equality Match` filter: should only contain the attribute & the condition")
	})

	// return-fast behavior: return true when at least one filter returns true
	// In this case, the first filter returns true, so the second filter is not
	// evaluated
	t.Run("(|(objectClass=posixAccount)(ERROR))", func(t *testing.T) {
		filter := &ber.Packet{
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
					Children: []*ber.Packet{
						{Value: "objectClass"},
						{Value: "posixAccount"},
					},
				},
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
				},
			},
		}
		_, err := filters.OrResolver(object, filter)
		require.NoError(t, err)
	})
}

func TestNotResolver(t *testing.T) {
	tests := []struct {
		filter   string
		expected func(t assert.TestingT, value bool, msgAndArgs ...interface{}) bool
	}{
		{
			filter:   "(!(objectClass=posixAccount))", // ! T
			expected: assert.False,
		},
		{
			filter:   "(!(objectClass=inetOrgPerson))", // ! F
			expected: assert.True,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			filter, err := goldap.CompileFilter(tt.filter)
			require.NoError(t, err)

			actual, err := filters.NotResolver(object, filter)
			require.NoError(t, err)
			tt.expected(t, actual)
		})
	}
}

func TestNotResolver_Error(t *testing.T) {
	t.Run("InvalidExpression", func(t *testing.T) {
		_, err := filters.NotResolver(object, &ber.Packet{Children: []*ber.Packet{}})
		require.EqualError(t, err, "invalid `Not` filter: should only contain one expression")

		_, err = filters.NotResolver(object, &ber.Packet{Children: []*ber.Packet{{}, {}, {}}})
		require.EqualError(t, err, "invalid `Not` filter: should only contain one expression")
	})

	t.Run("(!(ERROR))", func(t *testing.T) {
		filter := &ber.Packet{
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: goldap.FilterEqualityMatch},
				},
			},
		}
		_, err := filters.NotResolver(object, filter)
		require.EqualError(t, err, "invalid `Equality Match` filter: should only contain the attribute & the condition")
	})
}
