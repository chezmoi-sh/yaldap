package filters

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/exp/slices"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"

	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
)

func init() {
	berFilterResolvers[goldap.FilterSubstrings] = SubstringResolver
}

// SubstringResolver resolves LDAP FilterSubstrings expressions on the current entry.
func SubstringResolver(object ldap.Object, filter *ber.Packet) (bool, error) {
	if len(filter.Children) != 2 {
		return false, &Error{goldap.FilterSubstrings, fmt.Errorf("should only contain the attribute & the condition")}
	}

	attr, valid := filter.Children[0].Value.(string)
	if !valid || attr == "" {
		return false, &Error{goldap.FilterSubstrings, fmt.Errorf("invalid attribute: must be a valid non-empty string")}
	}

	// TODO: case-insensitive by default
	rxSubstr := "(?i)"
	for _, substring := range filter.Children[1].Children {
		value, valid := substring.Value.(string)
		if !valid {
			return false, &Error{goldap.FilterSubstrings, fmt.Errorf("internal error: wrong value type")}
		}

		switch substring.Tag {
		case goldap.FilterSubstringsInitial:
			rxSubstr += value + ".*"
		case goldap.FilterSubstringsAny:
			rxSubstr += ".*" + value + ".*"
		case goldap.FilterSubstringsFinal:
			rxSubstr += ".*" + value
		}
	}
	// NOTE: clean .*.* expression
	rxSubstr = strings.ReplaceAll(rxSubstr, ".*.*", ".*")

	rx, err := regexp.Compile(rxSubstr)
	if err != nil {
		return false, &Error{goldap.FilterSubstrings, fmt.Errorf("internal error: %w", err)}
	}

	if attr, exists := object.Attribute(attr); exists {
		return slices.IndexFunc(attr.Values(), func(s string) bool { return rx.MatchString(s) }) > -1, nil
	}
	return false, nil
}
