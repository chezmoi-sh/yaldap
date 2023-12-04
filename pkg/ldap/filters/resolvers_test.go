package filters_test

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/jimlambrt/gldap"
	. "github.com/moznion/go-optional"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

type filterResolverTestCase struct {
	name   string
	filter *ber.Packet
	result Option[bool]
}

func must[T any](x T, _ error) T { return x }

func (tc filterResolverTestCase) Run(t *testing.T, object ldap.Object, resolver filters.BerFilterExpressionResolver) {
	expected, _ := tc.result.Take()
	result, err := resolver(object, tc.filter)

	if tc.result.IsNone() {
		assert.Error(t, err)
	} else {
		require.NoError(t, err)
		assert.Equal(t, expected, result)
	}
}

type mockLdapObject map[string]ldap.Attribute

func (o mockLdapObject) DN() string                  { return "" }
func (o mockLdapObject) Attributes() ldap.Attributes { return ldap.Attributes(o) }
func (o mockLdapObject) Invalid() bool               { return false }
func (o mockLdapObject) Attribute(name string) (ldap.Attribute, bool) {
	return ldap.Attributes(o).Attribute(name)
}

func (o mockLdapObject) Search(gldap.Scope, string) ([]ldap.Object, error) {
	return nil, nil
}
func (o mockLdapObject) Bind(string) Option[bool]   { return Some(true) }
func (o mockLdapObject) CanAccessTo(dn string) bool { return true }

type mockLdapAttribute []string

func (a mockLdapAttribute) Values() []string { return a }
