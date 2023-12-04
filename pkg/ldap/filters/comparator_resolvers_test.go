package filters_test

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	. "github.com/moznion/go-optional"

	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

func TestGreaterOrEqualResolver(t *testing.T) {
	object := mockLdapObject{
		"memberOf":  mockLdapAttribute{"admin", "groups", "h4ck3r"},
		"listIds":   mockLdapAttribute{"1", "32", "5"},
		"mixedList": mockLdapAttribute{"234", "114", "64", " 398"},
	}

	tests := []filterResolverTestCase{
		{
			name:   "NumericComparisonSucceed",
			filter: must(goldap.CompileFilter("(listIds>=3)")), // 5, 32
			result: Some(true),
		},
		{
			name:   "WordComparisonSucceed",
			filter: must(goldap.CompileFilter("(memberOf>=a)")), // h4ck3r
			result: Some(true),
		},
		{
			name:   "MixedComparisonSucceed",
			filter: must(goldap.CompileFilter("(mixedList>=2)")), // 234, 114, 64
			result: Some(true),
		},
		{
			name:   "NumericComparisonFailed",
			filter: must(goldap.CompileFilter("(listIds>=300)")),
			result: Some(false),
		},
		{
			name:   "WordComparisonFailed",
			filter: must(goldap.CompileFilter("(memberOf>=z)")),
			result: Some(false),
		},
		{
			name:   "MixedComparisonFailed",
			filter: must(goldap.CompileFilter("(mixedList>=2907834)")),
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
			tt.Run(t, object, filters.GreaterOrEqualResolver)
		})
	}
}

func TestLessOrEqualResolver(t *testing.T) {
	object := mockLdapObject{
		"memberOf":  mockLdapAttribute{"admin", "groups", "h4ck3r"},
		"listIds":   mockLdapAttribute{"1", "32", "5"},
		"mixedList": mockLdapAttribute{"234", "114", "64", " 398"},
	}

	tests := []filterResolverTestCase{
		{
			name:   "NumericComparisonSucceed",
			filter: must(goldap.CompileFilter("(listIds<=3)")), // 1
			result: Some(true),
		},
		{
			name:   "WordComparisonSucceed",
			filter: must(goldap.CompileFilter("(memberOf<=b)")), // admin
			result: Some(true),
		},
		{
			name:   "MixedComparisonSucceed",
			filter: must(goldap.CompileFilter("(mixedList<=2)")), // ' 398'
			result: Some(true),
		},
		{
			name:   "NumericComparisonFailed",
			filter: must(goldap.CompileFilter("(listIds<=0)")),
			result: Some(false),
		},
		{
			name:   "WordComparisonFailed",
			filter: must(goldap.CompileFilter("(memberOf<=a)")),
			result: Some(false),
		},
		{
			name:   "MixedComparisonFailed",
			filter: must(goldap.CompileFilter("(mixedList<= )")),
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
			tt.Run(t, object, filters.LessOrEqualResolver)
		})
	}
}
