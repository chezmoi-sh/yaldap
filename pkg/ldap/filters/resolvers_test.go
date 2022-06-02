package filters_test

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/jimlambrt/gldap"
	. "github.com/moznion/go-optional"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

type filterResolverTestCase struct {
	name   string
	filter *ber.Packet
	result Option[bool]
}

func must[T any](x T, _ error) T { return x }

func (tc filterResolverTestCase) Run(t *testing.T, object yaldaplib.Object, resolver filters.BerFilterExpressionResolver) {
	expected, _ := tc.result.Take()
	result, err := resolver(object, tc.filter)

	if tc.result.IsNone() {
		assert.Error(t, err)
	} else {
		require.NoError(t, err)
		assert.Equal(t, expected, result)
	}
}

type mockLdapObject map[string]yaldaplib.Attribute

func (o mockLdapObject) DN() string                       { return "" }
func (o mockLdapObject) Attributes() yaldaplib.Attributes { return yaldaplib.Attributes(o) }
func (o mockLdapObject) Invalid() bool                    { return false }
func (o mockLdapObject) Attribute(name string) (yaldaplib.Attribute, bool) {
	return yaldaplib.Attributes(o).Attribute(name)
}
func (o mockLdapObject) Search(gldap.Scope, string) ([]yaldaplib.Object, error) {
	return nil, nil
}

type mockLdapAttribute []string

func (a mockLdapAttribute) Values() []string { return a }
