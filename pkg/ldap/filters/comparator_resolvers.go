package filters

import (
	"fmt"
	"strconv"
	"strings"

	ldap "github.com/chezmoi-sh/yaldap/pkg/ldap/directory"
	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"golang.org/x/exp/slices"
)

//nolint:gochecknoinits
func init() {
	berFilterResolvers[goldap.FilterGreaterOrEqual] = BerFilterExpressionResolver{resolve: GreaterOrEqualResolver}
	berFilterResolvers[goldap.FilterLessOrEqual] = BerFilterExpressionResolver{resolve: LessOrEqualResolver}
}

// compareFnc defines the comparison rule to apply on the condition and the entry attribute.
type compareFnc func(rhs string, attrs []string) bool

// GreaterOrEqualResolver resolves LDAP FilterGreaterOrEqual expressions on the current entry.
func GreaterOrEqualResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	greaterCompare := func(rhs string, attrs []string) bool {
		rhsI, rhsErr := strconv.Atoi(rhs)

		return slices.IndexFunc(attrs, func(lhs string) bool {
			lhsI, lhsErr := strconv.Atoi(lhs)
			if rhsErr == nil && lhsErr == nil {
				return lhsI >= rhsI
			}
			return lhs >= rhs
		}) > -1
	}

	match, err := compareResolver(greaterCompare, object, filter)
	if err != nil {
		return false, &Error{goldap.FilterGreaterOrEqual, err}
	}
	return match, nil
}

// LessOrEqualResolver resolves LDAP FilterLessOrEqual expressions on the current entry.
func LessOrEqualResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	lessCompare := func(rhs string, attrs []string) bool {
		rhsI, rhsErr := strconv.Atoi(rhs)

		return slices.IndexFunc(attrs, func(lhs string) bool {
			lhsI, lhsErr := strconv.Atoi(lhs)
			if rhsErr == nil && lhsErr == nil {
				return lhsI <= rhsI
			}
			return lhs <= rhs
		}) > -1
	}

	match, err := compareResolver(lessCompare, object, filter)
	if err != nil {
		return false, &Error{goldap.FilterLessOrEqual, err}
	}
	return match, nil
}

// comparatorResolver compare the current entry attributes with the given LDAP condition.
func compareResolver(fnc compareFnc, object ldap.Object, filter *ber.Packet) (bool, error) {
	if len(filter.Children) != 2 {
		return false, fmt.Errorf("should only contain the attribute & the condition")
	}

	attr, valid := filter.Children[0].Value.(string)
	if !valid || attr == "" {
		return false, fmt.Errorf("invalid attribute: must be a valid non-empty string")
	}
	condition, valid := filter.Children[1].Value.(string)
	if !valid {
		return false, fmt.Errorf("invalid condition: must be a valid string")
	}

	for key, values := range object.Attributes() {
		// NOTE: we need to compare the attribute name in a case-insensitive way.
		if strings.EqualFold(key, attr) {
			return fnc(condition, values), nil
		}
	}
	return false, nil
}
