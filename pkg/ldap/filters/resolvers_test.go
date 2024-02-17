package filters_test

import (
	"testing"

	ldap "github.com/chezmoi-sh/yaldap/pkg/ldap/directory"
	"github.com/chezmoi-sh/yaldap/pkg/ldap/directory/common"
	"github.com/chezmoi-sh/yaldap/pkg/ldap/filters"
	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var object = common.Object{
	ImplObject: common.ImplObject{
		DN: "uid=alice,ou=users,dc=example,dc=org",
		Attributes: ldap.Attributes{
			"uid":         []string{"alice"},
			"objectClass": []string{"posixAccount"},

			"cn":            []string{"Alice"},
			"sn":            []string{"Smith"},
			"uidNumber":     []string{"1000"},
			"gidNumber":     []string{"1000"},
			"homeDirectory": []string{"/home/alice", "/tmp/alice_temporary"},

			"mail": []string{
				"alice.smith@example.org",
				"as@example.org",
			},

			"memberOf": []string{"admin", "1000", "groups", " 398"},
		},
	},
}

func TestMatch(t *testing.T) {
	filter, err := goldap.CompileFilter("(uid=alice)")
	require.NoError(t, err)

	result, err := filters.Match(object, filter)
	require.NoError(t, err)
	assert.True(t, result)
}

func TestBerFilterExpressionResolver_Resolve(t *testing.T) {
	t.Run("nil filter", func(t *testing.T) {
		resolver := filters.BerFilterExpressionResolver{}
		_, err := resolver.Resolve(object, nil)
		require.EqualError(t, err, "invalid `<unknown>` filter: no filter provided")
	})

	t.Run("NoResolver", func(t *testing.T) {
		resolver := filters.BerFilterExpressionResolver{}
		_, err := resolver.Resolve(object, &ber.Packet{Identifier: ber.Identifier{Tag: 0xFFFFFFFFFFFFFFFF}})
		require.EqualError(t, err, "invalid `<unknown>` filter: not implemented")
	})
}
