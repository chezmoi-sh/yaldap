package filters

import (
	"strconv"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	phonetics "github.com/go-dedup/metaphone"
	goldap "github.com/go-ldap/ldap/v3"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
	"golang.org/x/exp/slices"
)

//nolint:gochecknoinits
func init() {
	berFilterResolvers[goldap.FilterApproxMatch] = BerFilterExpressionResolver{resolve: ApproxResolver}
	berFilterResolvers[goldap.FilterEqualityMatch] = BerFilterExpressionResolver{resolve: EqualResolver}
}

// ApproxResolver resolves LDAP FilterApproxMatch expressions on the current entry.
func ApproxResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	approxCompare := func(rhs string, attrs []string) bool {
		// Handle numeric values differently
		rhsI, rhsErr := strconv.Atoi(strings.TrimSpace(rhs))
		if rhsErr == nil {
			return slices.IndexFunc(attrs, func(lhs string) bool {
				lhsI, lhsErr := strconv.Atoi(strings.TrimSpace(lhs))
				return lhsErr == nil && lhsI == rhsI
			}) > -1
		}

		sdxcond := phonetics.EncodeMetaphone(rhs)
		return slices.IndexFunc(attrs, func(lhs string) bool { return phonetics.EncodeMetaphone(lhs) == sdxcond }) > -1
	}

	match, err := compareResolver(approxCompare, object, filter)
	if err != nil {
		return false, &Error{goldap.FilterApproxMatch, err}
	}
	return match, nil
}

// EqualResolver resolves LDAP FilterEqualityMatch expressions on the current entry.
func EqualResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	equalCompare := func(rhs string, attrs []string) bool {
		// case-insensitive by default
		rhs = strings.ToLower(rhs)

		return slices.IndexFunc(attrs, func(lhs string) bool { return strings.ToLower(lhs) == rhs }) > -1
	}

	match, err := compareResolver(equalCompare, object, filter)
	if err != nil {
		return false, &Error{goldap.FilterEqualityMatch, err}
	}
	return match, nil
}
