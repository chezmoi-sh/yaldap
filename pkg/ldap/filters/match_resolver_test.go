package filters_test

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

func TestApproxResolver(t *testing.T) {
	tests := []struct {
		filter   string
		expected func(t assert.TestingT, value bool, msgAndArgs ...interface{}) bool
	}{
		{
			filter:   "(memberOf~=admin)",
			expected: assert.True,
		},
		{
			filter:   "(memberOf~=unknown)",
			expected: assert.False,
		},
		{
			filter:   "(memberOf~=admun)",
			expected: assert.True,
		},
		{
			filter:   "(memberOf~=admunistrator)",
			expected: assert.False,
		},
		{
			filter:   "(uidNumber~=1000)",
			expected: assert.True,
		},
		{
			filter:   "(uidNumber~=1001)",
			expected: assert.False,
		},
		{
			filter:   "(memberOf~=398)",
			expected: assert.True,
		},

		{ // NOTE: case-insensitive attribute
			filter:   "(uidnumber~=1000)",
			expected: assert.True,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			filter, err := goldap.CompileFilter(tt.filter)
			require.NoError(t, err)

			result, err := filters.ApproxResolver(object, filter)
			require.NoError(t, err)
			tt.expected(t, result)
		})
	}
}

func TestApproxResolver_Error(t *testing.T) {
	t.Run("InvalidExpression", func(t *testing.T) {
		_, err := filters.ApproxResolver(object, &ber.Packet{Children: []*ber.Packet{}})
		require.EqualError(t, err, "invalid `Approx Match` filter: should only contain the attribute & the condition")

		_, err = filters.ApproxResolver(object, &ber.Packet{Children: []*ber.Packet{{}, {}, {}}})
		require.EqualError(t, err, "invalid `Approx Match` filter: should only contain the attribute & the condition")

		_, err = filters.ApproxResolver(object, &ber.Packet{Children: []*ber.Packet{{}, {Value: "3"}}})
		require.EqualError(t, err, "invalid `Approx Match` filter: invalid attribute: must be a valid non-empty string")

		_, err = filters.ApproxResolver(object, &ber.Packet{Children: []*ber.Packet{{Value: "memberOf"}, {}}})
		require.EqualError(t, err, "invalid `Approx Match` filter: invalid condition: must be a valid string")
	})

	t.Run("(password~=a)", func(t *testing.T) {
		filter, err := goldap.CompileFilter("(password~=a)")
		require.NoError(t, err)

		actual, err := filters.ApproxResolver(object, filter)
		require.NoError(t, err)
		assert.False(t, actual)
	})
}

func TestEqualResolver(t *testing.T) {
	tests := []struct {
		filter   string
		expected func(t assert.TestingT, value bool, msgAndArgs ...interface{}) bool
	}{
		{
			filter:   "(memberOf=admin)",
			expected: assert.True,
		},
		{
			filter:   "(memberOf=unknown)",
			expected: assert.False,
		},
		{
			filter:   "(memberOf=admun)",
			expected: assert.False,
		},
		{
			filter:   "(memberOf=admunistrator)",
			expected: assert.False,
		},
		{
			filter:   "(uidNumber=1000)",
			expected: assert.True,
		},
		{
			filter:   "(uidNumber=1001)",
			expected: assert.False,
		},
		{
			filter:   "(memberOf=398)",
			expected: assert.False,
		},

		{ // NOTE: case-insensitive attribute
			filter:   "(uidnumber=1000)",
			expected: assert.True,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			filter, err := goldap.CompileFilter(tt.filter)
			require.NoError(t, err)

			result, err := filters.EqualResolver(object, filter)
			require.NoError(t, err)
			tt.expected(t, result)
		})
	}
}

func TestEqualResolver_Error(t *testing.T) {
	t.Run("InvalidExpression", func(t *testing.T) {
		_, err := filters.EqualResolver(object, &ber.Packet{Children: []*ber.Packet{}})
		require.EqualError(t, err, "invalid `Equality Match` filter: should only contain the attribute & the condition")

		_, err = filters.EqualResolver(object, &ber.Packet{Children: []*ber.Packet{{}, {}, {}}})
		require.EqualError(t, err, "invalid `Equality Match` filter: should only contain the attribute & the condition")

		_, err = filters.EqualResolver(object, &ber.Packet{Children: []*ber.Packet{{}, {Value: "3"}}})
		require.EqualError(t, err, "invalid `Equality Match` filter: invalid attribute: must be a valid non-empty string")

		_, err = filters.EqualResolver(object, &ber.Packet{Children: []*ber.Packet{{Value: "memberOf"}, {}}})
		require.EqualError(t, err, "invalid `Equality Match` filter: invalid condition: must be a valid string")
	})

	t.Run("(password=a)", func(t *testing.T) {
		filter, err := goldap.CompileFilter("(password=a)")
		require.NoError(t, err)

		actual, err := filters.EqualResolver(object, filter)
		require.NoError(t, err)
		assert.False(t, actual)
	})
}
