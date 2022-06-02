package filters_test

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	. "github.com/moznion/go-optional"
	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

func TestSubstringResolver(t *testing.T) {
	object := mockLdapObject{
		"memberOf":  mockLdapAttribute{"admin", "groups", "h4ck3r"},
		"listIds":   mockLdapAttribute{"1", "32", "5"},
		"mixedList": mockLdapAttribute{"234", "114", "64", " 398"},
	}

	tests := []filterResolverTestCase{
		{name: "SubstringsInitialSucceed",
			filter: must(ldap.CompileFilter("(memberOf=ad*)")),
			result: Some(true)},
		{name: "SubstringsAnySucceed",
			filter: must(ldap.CompileFilter("(memberOf=*dm*)")),
			result: Some(true)},
		{name: "SubstringsFinalSucceed",
			filter: must(ldap.CompileFilter("(memberOf=*min)")),
			result: Some(true)},
		{name: "SubstringsFullSucceed",
			filter: must(ldap.CompileFilter("(memberOf=a*m*n)")),
			result: Some(true)},
		{name: "SubstringsInitialFailed",
			filter: must(ldap.CompileFilter("(memberOf=un*)")),
			result: Some(false)},
		{name: "SubstringsAnyFailed",
			filter: must(ldap.CompileFilter("(memberOf=*kno*)")),
			result: Some(false)},
		{name: "SubstringsFinalFailed",
			filter: must(ldap.CompileFilter("(memberOf=*own)")),
			result: Some(false)},
		{name: "SubstringsFullFailed",
			filter: must(ldap.CompileFilter("(memberOf=u*k*n)")),
			result: Some(false)},

		{name: "NoExpression",
			filter: &ber.Packet{Children: []*ber.Packet{}},
			result: None[bool]()},
		{name: "InvalidExpression",
			filter: &ber.Packet{Children: []*ber.Packet{{}, {}, {}}},
			result: None[bool]()},
		{name: "InvalidAttribute",
			filter: &ber.Packet{Children: []*ber.Packet{{}, {Value: "3"}}},
			result: None[bool]()},
		{name: "InvalidCondition",
			filter: &ber.Packet{Children: []*ber.Packet{{Value: "memberOf"}, {Children: []*ber.Packet{{}}}}},
			result: None[bool]()},
		{name: "AttributeNotFound",
			filter: &ber.Packet{Children: []*ber.Packet{{Value: "uid"}, {Value: "alice"}}},
			result: Some(false)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.Run(t, object, filters.SubstringResolver)
		})
	}
}
