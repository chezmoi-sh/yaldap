package filters

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
)

//nolint:gochecknoinits
func init() {
	berFilterResolvers[goldap.FilterAnd] = BerFilterExpressionResolver{resolve: AndResolver}
	berFilterResolvers[goldap.FilterOr] = BerFilterExpressionResolver{resolve: OrResolver}
	berFilterResolvers[goldap.FilterNot] = BerFilterExpressionResolver{resolve: NotResolver}
}

// AndResolver apply LDAP FilterAnd expressions on the given entry.
func AndResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	if len(filter.Children) == 0 {
		return false, nil
	}

	for _, subfilter := range filter.Children {
		match, err := Match(object, subfilter)
		if err != nil {
			return false, err
		}
		if !match {
			return false, nil
		}
	}
	return true, nil
}

// OrResolver apply LDAP FilterOr expressions on the given entry.
func OrResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	if len(filter.Children) == 0 {
		return false, nil
	}

	for _, subfilter := range filter.Children {
		match, err := Match(object, subfilter)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}

	return false, nil
}

// NotResolver apply LDAP FilterNot expressions on the given entry.
func NotResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	if len(filter.Children) != 1 {
		return false, &Error{goldap.FilterNot, fmt.Errorf("should only contain one expression")}
	}

	res, err := Match(object, filter.Children[0])
	return !res, err
}
