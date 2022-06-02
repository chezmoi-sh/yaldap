package filters

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
)

func init() {
	berFilterResolvers[ldap.FilterPresent] = PresentResolver
}

// PresentResolver resolves LDAP FilterPresent expressions on the current entry.
func PresentResolver(object yaldaplib.Object, filter *ber.Packet) (bool, error) {
	attr, valid := filter.Value.(string)
	if !valid || attr == "" {
		return false, &Error{ldap.FilterPresent, fmt.Errorf(errInvalidAttribute)}
	}

	_, exists := object.Attribute(attr)
	return exists, nil
}
