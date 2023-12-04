package filters_test

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	. "github.com/moznion/go-optional"

	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

func TestPresentResolver(t *testing.T) {
	object := mockLdapObject{
		"memberOf":  mockLdapAttribute{"admin", "groups", "h4ck3r"},
		"listIds":   mockLdapAttribute{"1", "32", "5"},
		"mixedList": mockLdapAttribute{"234", "114", "64", " 398"},
	}

	tests := []filterResolverTestCase{
		{
			name:   "AttrExists",
			filter: must(goldap.CompileFilter("(memberOf=*)")),
			result: Some(true),
		},
		{
			name:   "AttrDoesntExist",
			filter: must(goldap.CompileFilter("(uid=*)")),
			result: Some(false),
		},

		{
			name:   "InvalidExpression",
			filter: &ber.Packet{},
			result: None[bool](),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.Run(t, object, filters.PresentResolver)
		})
	}
}
