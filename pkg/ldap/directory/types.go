package directory

import (
	"github.com/jimlambrt/gldap"
	"github.com/moznion/go-optional"
)

type (
	// Directory contains all current LDAP object tree, accessible using a base DN.
	Directory interface {
		// BaseDN	returns the LDAP object represented by the given DN. If no object found, it returns nil.
		BaseDN(dn string) Object
	}

	// Object represents an LDAP object.
	Object interface {
		// DN returns the DN of the current object
		DN() string
		// Attributes returns the list of attributes of the current object.
		Attributes() Attributes
		// Attribute returns the named attribute and true if it exists, return nil and false otherwise.
		Attribute(name string) (Attribute, bool)
		// Search searches sub objects based on the given scope and filter.
		Search(scope gldap.Scope, filter string) ([]Object, error)
		// Invalid returns true if the current object is not a valid LDAP object
		Invalid() bool

		// Bind returns true if the current object is able to authenticate and the password is correct.
		// It returns false if the password is wrong and optional.None if it cannot be authenticated.
		Bind(password string) optional.Option[bool]
		// CanSearchOn returns true if the current object is able to perform a search on the given DB.
		CanAccessTo(dn string) bool
	}

	// Attribute represents an LDAP attribute.
	Attribute interface {
		Values() []string
	}
	Attributes map[string]Attribute
)

// ToMap returns a map of attributes' values.
func (attrs Attributes) ToMap() map[string][]string {
	attrsMap := map[string][]string{}

	for key, attr := range attrs {
		attrsMap[key] = attr.Values()
	}
	return attrsMap
}

// Attribute returns the named attribute and true if it exists, return nil and false otherwise.
func (attrs Attributes) Attribute(name string) (Attribute, bool) {
	if attrs == nil {
		return nil, false
	}
	attr, exist := attrs[name]
	return attr, exist
}
