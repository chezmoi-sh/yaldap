package filters

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
)

//nolint:gochecknoinits
func init() {
	goldap.FilterMap[0xFFFFFFFFFFFFFFFF] = "<unknown>"
}

var berFilterResolvers = map[ber.Tag]BerFilterExpressionResolver{}

// Match uses the given filter to check if the current entry matches it.
func Match(object ldap.Object, filter *ber.Packet) (bool, error) {
	return berFilterResolvers[filter.Tag].Resolve(object, filter)
}

// BerFilterExpressionResolver is a function wrapper that apply a specific type of LDAP filter expression on the
// given directory entry. It returns true if the filter match the current entry, false otherwise.
type BerFilterExpressionResolver struct {
	resolve func(object ldap.Object, filter *ber.Packet) (bool, error)
}

func (resolver BerFilterExpressionResolver) Resolve(object ldap.Object, filter *ber.Packet) (bool, error) {
	if filter == nil {
		return false, &Error{
			ber.Tag(0xFFFFFFFFFFFFFFFF),
			fmt.Errorf("no filter provided"),
		}
	}

	if resolver.resolve == nil {
		return false, &Error{
			filter.Tag,
			fmt.Errorf("not implemented"),
		}
	}
	return resolver.resolve(object, filter)
}

// An Error describes a failure to execute a filter resolver.
type Error struct {
	tag ber.Tag
	err error
}

func (err Error) Unwrap() error { return err.err }
func (err Error) Error() string {
	return fmt.Sprintf("invalid `%s` filter: %s", goldap.FilterMap[uint64(err.tag)], err.err)
}
