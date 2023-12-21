package directory

import (
	"github.com/jimlambrt/gldap"
)

type (
	// Directory contains all current LDAP object tree, accessible using a base DN.
	Directory interface {
		// BaseDN returns the LDAP object represented by the given DN. If no object found,
		// it returns nil.
		// If the given DN is empty, it returns the root object.
		BaseDN(dn string) Object
	}

	// Object represents an LDAP object.
	Object interface {
		// DN returns the DN of the current object
		DN() string
		// Attributes returns the list of attributes of the current object.
		Attributes() Attributes
		// Search searches sub objects based on the given scope and filter.
		Search(scope gldap.Scope, filter string) ([]Object, error)

		// Bind returns true if the current object is able to authenticate and the password is correct.
		// It returns false if the password is wrong and optional.None if it cannot be authenticated.
		Bind(password string) bool
		// CanSearchOn returns true if the current object is able to perform a search on the given DN.
		CanSearchOn(dn string) bool
	}

	// Attributes represents a list of LDAP named attributes.
	Attributes map[string][]string
)
