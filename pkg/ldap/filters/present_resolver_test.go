package filters_test

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

func TestPresentResolver(t *testing.T) {
	tests := []struct {
		filter   string
		expected func(t assert.TestingT, value bool, msgAndArgs ...interface{}) bool
	}{
		{
			filter:   "(memberOf=*)",
			expected: assert.True,
		},
		{
			filter:   "(password=*)",
			expected: assert.False,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			filter, err := goldap.CompileFilter(tt.filter)
			require.NoError(t, err)

			result, err := filters.PresentResolver(object, filter)
			require.NoError(t, err)
			tt.expected(t, result)
		})
	}
}

func TestPresentResolver_Error(t *testing.T) {
	t.Run("InvalidExpression", func(t *testing.T) {
		_, err := filters.PresentResolver(object, &ber.Packet{})
		require.EqualError(t, err, "invalid `Present` filter: invalid attribute: must be a valid non-empty string")

		_, err = filters.PresentResolver(object, &ber.Packet{Value: 0x00})
		require.EqualError(t, err, "invalid `Present` filter: invalid attribute: must be a valid non-empty string")
	})
}
