package filters

import (
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
)

//nolint:gochecknoinits
func init() {
	berFilterResolvers[goldap.FilterPresent] = BerFilterExpressionResolver{resolve: PresentResolver}
}

// PresentResolver resolves LDAP FilterPresent expressions on the current entry.
func PresentResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	attr, valid := filter.Value.(string)
	if !valid || attr == "" {
		return false, &Error{goldap.FilterPresent, fmt.Errorf("invalid attribute: must be a valid non-empty string")}
	}

	for key, values := range object.Attributes() {
		// NOTE: case-insensitive attribute
		if strings.EqualFold(key, attr) && len(values) > 0 {
			return true, nil
		}
	}
	return false, nil
}
