package common

import (
	"fmt"
	"sort"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/jimlambrt/gldap"
	"github.com/moznion/go-optional"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
	"github.com/xunleii/yaldap/pkg/ldap/filters"
)

type (
	// Object is a generic LDAP object implementation.
	// It wraps ImplObject in order to implement the ldap.Object interface.
	Object struct {
		// ImplObject contains all information about the object, but because we
		// want to keep the Object clean from any conflict and misundertanding,
		// we use a different name for the internal object.
		ImplObject
	}

	// ImplObject is a generic LDAP object implementation with all the required
	// properties to be used by a specific LDAP directory implementation.
	ImplObject struct {
		DN         string
		Attributes ldap.Attributes
		SubObjects map[string]*Object

		BindPasswords optional.Option[string]
		ACLs          ACLRuleSet
	}

	// ACLRule represents an ACL rule used to determine if a object can make search on
	// a specific DN.
	ACLRule struct {
		DistinguishedNameSuffix string
		Allowed                 bool
	}
	// ACLRuleSet is an ordered set of ACL rules, sorted by the most precise suffix.
	ACLRuleSet []ACLRule
)

// DN returns the DN of the current object.
func (obj Object) DN() string { return obj.ImplObject.DN }

// Attributes returns the list of attributes of the current object.
func (obj Object) Attributes() ldap.Attributes {
	if obj.ImplObject.Attributes == nil {
		return ldap.Attributes{}
	}
	return obj.ImplObject.Attributes
}

// Search searches sub objects based on the given scope and filter.
// Depending on the scope, the search will be more or less precise :
// - gldap.BaseObject: only the current object will be searched
// - gldap.SingleLevel: the current object and its children will be searched
// - gldap.WholeSubtree: the current object and all its descendants will be searched.
func (obj Object) Search(scope gldap.Scope, filter string) ([]ldap.Object, error) {
	packet, err := goldap.CompileFilter(filter)
	if nil != err {
		return nil, fmt.Errorf("invalid search filter: %w", err)
	}
	return obj.search(scope, packet)
}

// Bind returns true if the current object is able to authenticate and the password is correct.
// It returns false if the password is wrong and optional.None if it cannot be authenticated.
func (obj Object) Bind(password string) bool {
	if obj.BindPasswords.IsNone() {
		return false
	}

	return obj.BindPasswords.Unwrap() == password
}

// CanSearchOn returns true if the current object is able to perform a search on the given DN.
func (obj Object) CanSearchOn(dn string) bool {
	for _, rule := range obj.ACLs {
		if strings.HasSuffix(dn, rule.DistinguishedNameSuffix) {
			return rule.Allowed
		}
	}
	return false
}

// search runs a search on the current object and its children, based on the
// given scope and filter.
// Depending on the scope, the search will be more or less precise :
// - gldap.BaseObject: only the current object will be searched
// - gldap.SingleLevel: the current object and its children will be searched
// - gldap.WholeSubtree: the current object and all its descendants will be searched.
func (obj Object) search(scope gldap.Scope, filter *ber.Packet) (objects []ldap.Object, err error) {
	if match, err := filters.Match(&obj, filter); err != nil {
		return nil, err
	} else if match {
		objects = append(objects, &obj)
	}

	switch scope {
	case gldap.BaseObject:
		return objects, nil
	case gldap.SingleLevel:
		scope = gldap.BaseObject
	case gldap.WholeSubtree:
		// Nothing to do
	}

	for _, entry := range obj.SubObjects {
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

// AddAttribute adds the given values to the named attribute of the current object.
func (obj *ImplObject) AddAttribute(name string, values ...string) {
	if obj.Attributes == nil {
		obj.Attributes = ldap.Attributes{}
	}
	obj.Attributes[name] = append(obj.Attributes[name], values...)
}

// AddACLRule adds the given ACL rule to the current object at the right position,
// following the DN suffix order.
func (obj *ImplObject) AddACLRule(rule ...ACLRule) {
	obj.ACLs = append(obj.ACLs, rule...)
	sort.Sort(obj.ACLs)
}

// Less returns true if the suffix of the rule at index i is more precise than
// the one at index j.
func (set ACLRuleSet) Less(i, j int) bool {
	lhs, rhs := set[i].DistinguishedNameSuffix, set[j].DistinguishedNameSuffix

	if strings.Count(lhs, ",") != strings.Count(rhs, ",") {
		return strings.Count(lhs, ",") > strings.Count(rhs, ",")
	}
	if cmp := strings.Compare(lhs, rhs); cmp != 0 {
		return cmp < 0
	}
	return !set[i].Allowed
}
func (set ACLRuleSet) Len() int      { return len(set) }
func (set ACLRuleSet) Swap(i, j int) { set[i], set[j] = set[j], set[i] }
