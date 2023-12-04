package filters

import (
	"strings"

	"golang.org/x/exp/slices"

	ber "github.com/go-asn1-ber/asn1-ber"
	phonetics "github.com/go-dedup/metaphone"
	goldap "github.com/go-ldap/ldap/v3"

	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
)

func init() {
	berFilterResolvers[goldap.FilterApproxMatch] = ApproxResolver
	berFilterResolvers[goldap.FilterEqualityMatch] = EqualResolver
}

// ApproxResolver resolves LDAP FilterApproxMatch expressions on the current entry.
func ApproxResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	approxCompare := func(cond string, attr ldap.Attribute) bool {
		sdxcond := phonetics.EncodeMetaphone(cond)
		return slices.IndexFunc(attr.Values(), func(attr string) bool { return phonetics.EncodeMetaphone(attr) == sdxcond }) > -1
	}

	match, err := compareResolver(approxCompare, object, filter)
	if err != nil {
		return false, &Error{goldap.FilterApproxMatch, err}
	}
	return match, nil
}

// EqualResolver resolves LDAP FilterEqualityMatch expressions on the current entry.
func EqualResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	equalCompare := func(cond string, attr ldap.Attribute) bool {
		// TODO: case-insensitive by default
		cond = strings.ToLower(cond)

		return slices.IndexFunc(attr.Values(), func(attr string) bool { return strings.ToLower(attr) == cond }) > -1
	}

	match, err := compareResolver(equalCompare, object, filter)
	if err != nil {
		return false, &Error{goldap.FilterEqualityMatch, err}
	}
	return match, nil
}
