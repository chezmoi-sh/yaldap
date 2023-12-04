package filters

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	. "github.com/moznion/go-optional"

	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
)

func init() {
	berFilterResolvers[goldap.FilterAnd] = AndResolver
	berFilterResolvers[goldap.FilterOr] = OrResolver
	berFilterResolvers[goldap.FilterNot] = NotResolver
}

// AndResolver apply LDAP FilterAnd expressions on the given entry.
func AndResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	// NOTE: AND resolver MUST fail when ANY subfilter failed
	rules := booleanRules{true: None[bool](), false: Some(false)}

	match, err := booleanResolver(rules, object, filter)
	return match.TakeOr(true), err
}

// OrResolver apply LDAP FilterOr expressions on the given entry.
func OrResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	// NOTE: OR resolver MUST fail only if ALL subfilter failed
	rules := booleanRules{true: Some(true), false: None[bool]()}

	match, err := booleanResolver(rules, object, filter)
	return match.TakeOr(false), err
}

// NotResolver apply LDAP FilterNot expressions on the given entry.
func NotResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	if len(filter.Children) != 1 {
		return false, &Error{goldap.FilterPresent, fmt.Errorf("should only contain one expression")}
	}

	res, err := berFilterResolvers[filter.Children[0].Tag](object, filter.Children[0])
	return !res, err
}

// booleanRules defines the rule to apply on filter matching result.
type booleanRules map[bool]Option[bool]

// booleanResolver execute the boolean LDAP filters (AND, OR) on the current entry. It uses a simple matrix boolean
// to program the boolean behaviour.
func booleanResolver(rules booleanRules, object ldap.Object, filter *ber.Packet) (Option[bool], error) {
	if len(filter.Children) == 0 {
		return Some(false), nil
	}

	for _, subfilter := range filter.Children {
		match, err := berFilterResolvers[subfilter.Tag](object, subfilter)
		if err != nil {
			return None[bool](), err
		}

		switch {
		case rules[match].IsSome():
			return rules[match], nil
		}
	}
	return None[bool](), nil
}
