package naive

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/jimlambrt/gldap"
	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

// Object implements the ldap.Object interface.
type Object struct {
	dn         string
	attributes yaldaplib.Attributes

	children map[string]*Object
}

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

// Attribute implements the ldap.Attribute interface.
type Attribute []string

func (a Attribute) Values() []string { return a }
