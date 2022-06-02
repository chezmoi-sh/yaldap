package filters

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
)

func init() {
	berFilterResolvers[ldap.FilterExtensibleMatch] = func(yaldaplib.Object, *ber.Packet) (bool, error) {
		return false, fmt.Errorf("`%s` filter not implemented", ldap.FilterMap[ldap.FilterEqualityMatch])
	}
}

// BerFilterExpressionResolver is a function that apply a specific type of LDAP filter expression on the given
// directory entry. It returns true if the filter match the current entry, false otherwise.
type BerFilterExpressionResolver func(object yaldaplib.Object, filter *ber.Packet) (bool, error)

var berFilterResolvers = map[ber.Tag]BerFilterExpressionResolver{}

// AddFilterResolvers adds a custom filter resolver.
func AddFilterResolvers(tag ber.Tag, resolver BerFilterExpressionResolver) {
	if _, exists := berFilterResolvers[tag]; !exists {
		berFilterResolvers[tag] = resolver
	}
}

// Match uses the given filter to check if the current entry matches it.
func Match(object yaldaplib.Object, filter *ber.Packet) (bool, error) {
	if filter == nil {
		return false, nil
	}

	return berFilterResolvers[filter.Tag](object, filter)
}

// An Error describes a failure to execute a filter resolver.
type Error struct {
	tag ber.Tag
	err error
}

func (err Error) Unwrap() error { return err.err }
func (err Error) Error() string {
	return fmt.Sprintf("invalid `%s` filter: %s", ldap.FilterMap[uint64(err.tag)], err.err)
}

const (
	errContainOnlyOneExpression      = "should only contain one expression"
	errContainOnlyAttrCondExpression = "should only contain the attribute & the condition"
	errInvalidAttribute              = "invalid attribute: must be a valid non-empty string"
	errInvalidCondition              = "invalid condition: must be a valid string"
	errWrongValueType                = "internal error: wrong value type"
)
