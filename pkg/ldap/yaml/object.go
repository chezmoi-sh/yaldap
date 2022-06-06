package yaml

import (
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/jimlambrt/gldap"
	"github.com/moznion/go-optional"
	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

type (
	// Object implements the ldap.Object interface.
	Object struct {
		dn         string
		attributes yaldaplib.Attributes

		bindPasswords []string
		acls          objectAclList

		children map[string]*Object
	}
)

func (o Object) DN() string                       { return o.dn }
func (o Object) Attributes() yaldaplib.Attributes { return o.attributes }
func (o Object) Attribute(name string) (yaldaplib.Attribute, bool) {
	return o.attributes.Attribute(name)
}
func (o *Object) Invalid() bool { return o == nil }

func (o *Object) Search(scope gldap.Scope, filter string) ([]yaldaplib.Object, error) {
	if o == nil {
		return nil, nil
	}

	packet, err := ldap.CompileFilter(filter)
	if err != nil {
		return nil, fmt.Errorf("invalid search filter: %w", err)
	}
	return o.search(scope, packet)
}

func (o *Object) search(scope gldap.Scope, filter *ber.Packet) (objects []yaldaplib.Object, err error) {
	if match, err := filters.Match(o, filter); err != nil {
		return nil, err
	} else if match {
		objects = append(objects, o)
	}

	switch scope {
	case gldap.BaseObject:
		return objects, nil
	case gldap.SingleLevel:
		scope = gldap.BaseObject
	case gldap.WholeSubtree:
		// Nothing to do
	}

	for _, entry := range o.children {
		res, err := entry.search(scope, filter)
		switch {
		case err != nil:
			return nil, err
		case len(res) > 0:
			objects = append(objects, res...)
		}
	}
	return objects, nil
}

func (o Object) Bind(password string) optional.Option[bool] {
	if o.bindPasswords == nil {
		return optional.None[bool]()
	}

	for _, bindPassword := range o.bindPasswords {
		attr, exist := o.Attribute(bindPassword)
		if !exist || len(attr.Values()) == 0 {
			continue
		}

		for _, attempt := range attr.Values() {
			if attempt == password {
				return optional.Some(true)
			}
		}
	}

	return optional.Some(false)
}

func (o Object) CanAccessTo(dn string) bool { return o.acls.canAccessTo(dn) }

// Attribute implements the ldap.Attribute interface.
type Attribute []string

func (a Attribute) Values() []string { return a }

type (
	// objectAclList contains the list of allowed DN on which the object can perform a search.
	objectAclList []objectAclRule
	// objectAclRule represent an ACL rule.
	objectAclRule struct {
		suffix  string
		allowed bool
	}
)

func (o objectAclList) Len() int { return len(o) }
func (o objectAclList) Less(i, j int) bool {
	// NOTE: the most precise suffix is, the higher priority it will have
	return strings.Count(o[i].suffix, ",") > strings.Count(o[j].suffix, ",")
}
func (o objectAclList) Swap(i, j int) { o[i], o[j] = o[j], o[i] }

func (o objectAclList) canAccessTo(dn string) bool {
	if len(o) == 0 {
		return false
	}

	for _, rule := range o {
		if strings.HasSuffix(dn, rule.suffix) {
			return rule.allowed
		}
	}
	return false
}
