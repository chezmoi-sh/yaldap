package filters

import (
	"fmt"
	"regexp"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
	"golang.org/x/exp/slices"
)

func init() {
	berFilterResolvers[ldap.FilterSubstrings] = SubstringResolver
}

// SubstringResolver resolves LDAP FilterSubstrings expressions on the current entry.
func SubstringResolver(object yaldaplib.Object, filter *ber.Packet) (bool, error) {
	if len(filter.Children) != 2 {
		return false, &Error{ldap.FilterSubstrings, fmt.Errorf(errContainOnlyAttrCondExpression)}
	}

	attr, valid := filter.Children[0].Value.(string)
	if !valid || attr == "" {
		return false, &Error{ldap.FilterSubstrings, fmt.Errorf(errInvalidAttribute)}
	}

	// TODO: case-insensitive by default
	var rxSubstr = "(?i)"
	for _, substring := range filter.Children[1].Children {
		value, valid := substring.Value.(string)
		if !valid {
			return false, &Error{ldap.FilterSubstrings, fmt.Errorf(errWrongValueType)}
		}

		switch substring.Tag {
		case ldap.FilterSubstringsInitial:
			rxSubstr += value + ".*"
		case ldap.FilterSubstringsAny:
			rxSubstr += ".*" + value + ".*"
		case ldap.FilterSubstringsFinal:
			rxSubstr += ".*" + value
		}
	}
	// NOTE: clean .*.* expression
	rxSubstr = strings.ReplaceAll(rxSubstr, ".*.*", ".*")

	rx, err := regexp.Compile(rxSubstr)
	if err != nil {
		return false, &Error{ldap.FilterSubstrings, fmt.Errorf("internal error: %w", err)}
	}

	if attr, exists := object.Attribute(attr); exists {
		return slices.IndexFunc(attr.Values(), func(s string) bool { return rx.MatchString(s) }) > -1, nil
	}
	return false, nil
}
