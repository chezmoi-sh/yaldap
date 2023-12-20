package utils

import "github.com/jimlambrt/gldap"

// LDAPScopes maps gldap.Scope to string for logging
// purposes.
var LDAPScopes = map[gldap.Scope]string{
	gldap.BaseObject:   "base",
	gldap.SingleLevel:  "one",
	gldap.WholeSubtree: "sub",
}
