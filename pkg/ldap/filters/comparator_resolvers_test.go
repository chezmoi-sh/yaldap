package filters_test

import (
	"testing"

	"github.com/chezmoi-sh/yaldap/pkg/ldap/filters"
	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGreaterOrEqualResolver(t *testing.T) {
	tests := []struct {
		filter   string
		expected func(t assert.TestingT, value bool, msgAndArgs ...interface{}) bool
	}{
		{
			filter:   "(uidNumber>=-1)",
			expected: assert.True,
		},
		{
			filter:   "(uidNumber>=1000)",
			expected: assert.True,
		},
		{
			filter:   "(uidNumber>=1001)",
			expected: assert.False,
		},
		{
			filter:   "(mail>=alice.smith@example.org)",
			expected: assert.True,
		},
		{
			filter:   "(mail>=bob.smith@example.org)",
			expected: assert.False,
		},
		{
			filter:   "(memberOf>=2)",
			expected: assert.True,
		},
		{
			filter:   "(memberOf>=2907834)",
			expected: assert.True,
		},
		{
			filter:   "(memberOf>=z)",
			expected: assert.False,
		},

		{ // NOTE: case-insensitive attribute
			filter:   "(uidnumber>=-1)",
			expected: assert.True,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			filter, err := goldap.CompileFilter(tt.filter)
			require.NoError(t, err)

			actual, err := filters.GreaterOrEqualResolver(object, filter)
			require.NoError(t, err)
			tt.expected(t, actual)
		})
	}
}

func TestGreaterOrEqualResolver_Error(t *testing.T) {
	t.Run("InvalidExpression", func(t *testing.T) {
		_, err := filters.GreaterOrEqualResolver(object, &ber.Packet{Children: []*ber.Packet{}})
		require.EqualError(t, err, "invalid `Greater Or Equal` filter: should only contain the attribute & the condition")

		_, err = filters.GreaterOrEqualResolver(object, &ber.Packet{Children: []*ber.Packet{{}, {}, {}}})
		require.EqualError(t, err, "invalid `Greater Or Equal` filter: should only contain the attribute & the condition")

		_, err = filters.GreaterOrEqualResolver(object, &ber.Packet{Children: []*ber.Packet{{}, {Value: "3"}}})
		require.EqualError(t, err, "invalid `Greater Or Equal` filter: invalid attribute: must be a valid non-empty string")

		_, err = filters.GreaterOrEqualResolver(object, &ber.Packet{Children: []*ber.Packet{{Value: "memberOf"}, {}}})
		require.EqualError(t, err, "invalid `Greater Or Equal` filter: invalid condition: must be a valid string")
	})

	t.Run("(password>=a)", func(t *testing.T) {
		filter, err := goldap.CompileFilter("(password>=a)")
		require.NoError(t, err)

		actual, err := filters.GreaterOrEqualResolver(object, filter)
		require.NoError(t, err)
		assert.False(t, actual)
	})
}

func TestLessOrEqualResolver(t *testing.T) {
	tests := []struct {
		filter   string
		expected func(t assert.TestingT, value bool, msgAndArgs ...interface{}) bool
	}{
		{
			filter:   "(uidNumber<=-1)",
			expected: assert.False,
		},
		{
			filter:   "(uidNumber<=1000)",
			expected: assert.True,
		},
		{
			filter:   "(uidNumber<=1001)",
			expected: assert.True,
		},
		{
			filter:   "(mail<=alice.smith@example.org)",
			expected: assert.True,
		},
		{
			filter:   "(mail<= bob.smith@example.org)",
			expected: assert.False,
		},
		{
			filter:   "(memberOf<=2)", // less than " 398"
			expected: assert.True,
		},
		{
			filter:   "(memberOf<=2907834)", // less than " 398"
			expected: assert.True,
		},
		{
			filter:   "(memberOf<= )",
			expected: assert.False,
		},

		{ // NOTE: case-insensitive attribute
			filter:   "(uidnumber<=1000)",
			expected: assert.True,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			filter, err := goldap.CompileFilter(tt.filter)
			require.NoError(t, err)

			actual, err := filters.LessOrEqualResolver(object, filter)
			require.NoError(t, err)
			tt.expected(t, actual)
		})
	}
}

func TestLessOrEqualResolver_Error(t *testing.T) {
	t.Run("InvalidExpression", func(t *testing.T) {
		_, err := filters.LessOrEqualResolver(object, &ber.Packet{Children: []*ber.Packet{}})
		require.EqualError(t, err, "invalid `Less Or Equal` filter: should only contain the attribute & the condition")

		_, err = filters.LessOrEqualResolver(object, &ber.Packet{Children: []*ber.Packet{{}, {}, {}}})
		require.EqualError(t, err, "invalid `Less Or Equal` filter: should only contain the attribute & the condition")

		_, err = filters.LessOrEqualResolver(object, &ber.Packet{Children: []*ber.Packet{{}, {Value: "3"}}})
		require.EqualError(t, err, "invalid `Less Or Equal` filter: invalid attribute: must be a valid non-empty string")

		_, err = filters.LessOrEqualResolver(object, &ber.Packet{Children: []*ber.Packet{{Value: "memberOf"}, {}}})
		require.EqualError(t, err, "invalid `Less Or Equal` filter: invalid condition: must be a valid string")
	})

	t.Run("(password<=a)", func(t *testing.T) {
		filter, err := goldap.CompileFilter("(password<=a)")
		require.NoError(t, err)

		actual, err := filters.LessOrEqualResolver(object, filter)
		require.NoError(t, err)
		assert.False(t, actual)
	})
}
