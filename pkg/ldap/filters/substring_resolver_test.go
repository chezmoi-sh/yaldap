package filters_test

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

func TestSubstringResolver(t *testing.T) {
	tests := []struct {
		filter   string
		expected func(t assert.TestingT, value bool, msgAndArgs ...interface{}) bool
	}{
		{
			filter:   "(memberOf=ad*)",
			expected: assert.True,
		},
		{
			filter:   "(memberOf=*dm*)",
			expected: assert.True,
		},
		{
			filter:   "(memberOf=*min)",
			expected: assert.True,
		},
		{
			filter:   "(memberOf=a*m*n)",
			expected: assert.True,
		},
		{
			filter:   "(memberOf=un*)",
			expected: assert.False,
		},
		{
			filter:   "(memberOf=*kno*)",
			expected: assert.False,
		},
		{
			filter:   "(memberOf=*own)",
			expected: assert.False,
		},
		{
			filter:   "(memberOf=u*k*n)",
			expected: assert.False,
		},

		{ // NOTE: case-insensitive attribute
			filter:   "(memberof=ad*)",
			expected: assert.True,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			filter, err := goldap.CompileFilter(tt.filter)
			require.NoError(t, err)

			result, err := filters.SubstringResolver(object, filter)
			require.NoError(t, err)
			tt.expected(t, result)
		})
	}
}

func TestSubstringResolver_Error(t *testing.T) {
	t.Run("InvalidExpression", func(t *testing.T) {
		_, err := filters.SubstringResolver(object, &ber.Packet{})
		require.EqualError(t, err, "invalid `Substrings` filter: should only contain the attribute & the condition")

		_, err = filters.SubstringResolver(object, &ber.Packet{Children: []*ber.Packet{{}, {}, {}}})
		require.EqualError(t, err, "invalid `Substrings` filter: should only contain the attribute & the condition")

		_, err = filters.SubstringResolver(object, &ber.Packet{Children: []*ber.Packet{{}, {Value: "3"}}})
		require.EqualError(t, err, "invalid `Substrings` filter: invalid attribute: must be a valid non-empty string")
	})

	t.Run("(password=*a)", func(t *testing.T) {
		filter, err := goldap.CompileFilter("(password=*a)")
		require.NoError(t, err)

		actual, err := filters.SubstringResolver(object, filter)
		require.NoError(t, err)
		assert.False(t, actual)
	})
}
