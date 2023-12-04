package filters

import (
	"fmt"
	"strconv"

	"golang.org/x/exp/slices"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"

	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
)

func init() {
	berFilterResolvers[goldap.FilterGreaterOrEqual] = GreaterOrEqualResolver
	berFilterResolvers[goldap.FilterLessOrEqual] = LessOrEqualResolver
}

// GreaterOrEqualResolver resolves LDAP FilterGreaterOrEqual expressions on the current entry.
func GreaterOrEqualResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	greaterCompare := func(cond string, attr ldap.Attribute) bool {
		condi, conderr := strconv.Atoi(cond)

		return slices.IndexFunc(attr.Values(), func(attr string) bool {
			attri, attrerr := strconv.Atoi(attr)
			if conderr == nil && attrerr == nil {
				return attri >= condi
			}
			return attr > cond
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
	lessCompare := func(cond string, attr ldap.Attribute) bool {
		condi, conderr := strconv.Atoi(cond)

		return slices.IndexFunc(attr.Values(), func(attr string) bool {
			attri, attrerr := strconv.Atoi(attr)
			if conderr == nil && attrerr == nil {
				return attri <= condi
			}
			return attr < cond
		}) > -1
	}

	match, err := compareResolver(lessCompare, object, filter)
	if err != nil {
		return false, &Error{goldap.FilterLessOrEqual, err}
	}
	return match, nil
}

// compareFnc defines the comparison rule to apply on the condition and the entry attribute
type compareFnc func(condition string, attrs ldap.Attribute) bool

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

	if attr, exists := object.Attribute(attr); exists {
		return fnc(condition, attr), nil
	}
	return false, nil
}
