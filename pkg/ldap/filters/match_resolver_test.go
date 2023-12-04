package filters_test

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	. "github.com/moznion/go-optional"

	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

func TestApproxResolver(t *testing.T) {
	object := mockLdapObject{
		"memberOf":  mockLdapAttribute{"admin", "groups", "h4ck3r"},
		"listIds":   mockLdapAttribute{"1", "32", "5"},
		"mixedList": mockLdapAttribute{"234", "114", "64", " 398"},
	}

	tests := []filterResolverTestCase{
		{
			name:   "Equality",
			filter: must(goldap.CompileFilter("(memberOf=admin)")),
			result: Some(true),
		},
		{
			name:   "NotFound",
			filter: must(goldap.CompileFilter("(memberOf=unknown)")),
			result: Some(false),
		},
		{
			name:   "Misspelling",
			filter: must(goldap.CompileFilter("(memberOf=admun)")),
			result: Some(true),
		},
		{
			name:   "Misspelling2",
			filter: must(goldap.CompileFilter("(memberOf=admunistrator)")),
			result: Some(false),
		},

		{
			name:   "NoExpression",
			filter: &ber.Packet{Children: []*ber.Packet{}},
			result: None[bool](),
		},
		{
			name:   "InvalidExpression",
			filter: &ber.Packet{Children: []*ber.Packet{{}, {}, {}}},
			result: None[bool](),
		},
		{
			name:   "InvalidAttribute",
			filter: &ber.Packet{Children: []*ber.Packet{{}, {Value: "3"}}},
			result: None[bool](),
		},
		{
			name:   "InvalidCondition",
			filter: &ber.Packet{Children: []*ber.Packet{{Value: "listIds"}, {}}},
			result: None[bool](),
		},
		{
			name:   "AttributeNotFound",
			filter: &ber.Packet{Children: []*ber.Packet{{Value: "uid"}, {Value: "alice"}}},
			result: Some(false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.Run(t, object, filters.ApproxResolver)
		})
	}
}

func TestEqualResolver(t *testing.T) {
	object := mockLdapObject{
		"memberOf":  mockLdapAttribute{"admin", "groups", "h4ck3r"},
		"listIds":   mockLdapAttribute{"1", "32", "5"},
		"mixedList": mockLdapAttribute{"234", "114", "64", " 398"},
	}

	tests := []filterResolverTestCase{
		{
			name:   "Equality",
			filter: must(goldap.CompileFilter("(memberOf=admin)")),
			result: Some(true),
		},
		{
			name:   "NotFound",
			filter: must(goldap.CompileFilter("(memberOf=unknown)")),
			result: Some(false),
		},
		{
			name:   "Misspelling",
			filter: must(goldap.CompileFilter("(memberOf=admun)")),
			result: Some(false),
		},
		{
			name:   "Misspelling2",
			filter: must(goldap.CompileFilter("(memberOf=admunistrator)")),
			result: Some(false),
		},

		{
			name:   "NoExpression",
			filter: &ber.Packet{Children: []*ber.Packet{}},
			result: None[bool](),
		},
		{
			name:   "InvalidExpression",
			filter: &ber.Packet{Children: []*ber.Packet{{}, {}, {}}},
			result: None[bool](),
		},
		{
			name:   "InvalidAttribute",
			filter: &ber.Packet{Children: []*ber.Packet{{}, {Value: "3"}}},
			result: None[bool](),
		},
		{
			name:   "InvalidCondition",
			filter: &ber.Packet{Children: []*ber.Packet{{Value: "listIds"}, {}}},
			result: None[bool](),
		},
		{
			name:   "AttributeNotFound",
			filter: &ber.Packet{Children: []*ber.Packet{{Value: "uid"}, {Value: "alice"}}},
			result: Some(false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.Run(t, object, filters.EqualResolver)
		})
	}
}
