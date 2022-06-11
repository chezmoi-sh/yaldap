package yaml

import (
	"sort"
	"testing"

	"github.com/jimlambrt/gldap"
	"github.com/moznion/go-optional"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
)

func TestDirectoryEntry_Search(t *testing.T) {
	yaml := `
l1:a:
  .@attr1: true
  .@attr2: true
  l2:a:
    .@attr1: true
    .@attr2: false
    l3:a:
      .@attr2: false
    l3:b:
      .@attr1: true
      .@attr2: false
      .@uniq: yes
  l2:b:
    .@attr2: true
  l2:c:
    .@attr1: false
    .@attr2: true
    l3:a:
      l4:a:
        .@attr1: true
        .@attr2: false
`
	directory, _ := NewDirectory([]byte(yaml))
	object := directory.BaseDN("l1=a")

	tests := []struct {
		name     string
		scope    gldap.Scope
		filter   string
		expected []string
	}{
		{name: "ExistsOnBaseObject",
			scope:    gldap.BaseObject,
			filter:   "(attr1=*)",
			expected: []string{"l1=a"}},
		{name: "ExistsOnSingleLevel",
			scope:    gldap.SingleLevel,
			filter:   "(attr1=*)",
			expected: []string{"l1=a", "l2=a,l1=a", "l2=c,l1=a"}},
		{name: "ExistsOnWholeSubtree",
			scope:    gldap.WholeSubtree,
			filter:   "(attr1=*)",
			expected: []string{"l1=a", "l2=a,l1=a", "l3=b,l2=a,l1=a", "l2=c,l1=a", "l4=a,l3=a,l2=c,l1=a"}},
		{name: "NotExistsOrAttr2IsFalseOnBaseObject",
			scope:    gldap.BaseObject,
			filter:   "(|(!attr1=*)(attr2=false))",
			expected: []string{}},
		{name: "NotExistsOrAttr2IsFalseOnSingleLevel",
			scope:    gldap.SingleLevel,
			filter:   "(|(!attr1=*)(attr2=false))",
			expected: []string{"l2=b,l1=a", "l2=a,l1=a"}},
		{name: "NotExistsOrAttr2IsFalseOnWholeSubtree",
			scope:    gldap.WholeSubtree,
			filter:   "(|(!attr1=*)(attr2=false))",
			expected: []string{"l2=a,l1=a", "l3=a,l2=a,l1=a", "l3=b,l2=a,l1=a", "l2=b,l1=a", "l3=a,l2=c,l1=a", "l4=a,l3=a,l2=c,l1=a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs, err := object.Search(tt.scope, tt.filter)
			require.NoError(t, err)

			var dns []string
			for _, obj := range objs {
				dns = append(dns, obj.DN())
			}

			assert.ElementsMatch(t, tt.expected, dns)
		})
	}
}

func TestObject_Nil_Search(t *testing.T) {
	objs, err := (*Object)(nil).Search(gldap.BaseObject, "")
	assert.Empty(t, objs)
	assert.NoError(t, err)
}

func TestObject_Bind(t *testing.T) {
	tests := []struct {
		name     string
		object   Object
		password string
		expected optional.Option[bool]
	}{
		{name: "ValidPassword",
			object: Object{
				bindPasswords: []string{"password"},
				attributes:    map[string]yaldaplib.Attribute{"password": Attribute{"password"}},
			},
			password: "password",
			expected: optional.Some(true)},
		{name: "ValidMultiPassword",
			object: Object{
				bindPasswords: []string{"password"},
				attributes:    map[string]yaldaplib.Attribute{"password": Attribute{"password", "another"}},
			},
			password: "another",
			expected: optional.Some(true)},
		{name: "ValidMultiPasswordAttribute",
			object: Object{
				bindPasswords: []string{"password", "userPasswd"},
				attributes: map[string]yaldaplib.Attribute{
					"password":   Attribute{},
					"userPasswd": Attribute{"password"},
				},
			},
			password: "password",
			expected: optional.Some(true)},

		{name: "NoBindProperty",
			object: Object{
				attributes: map[string]yaldaplib.Attribute{
					"password": Attribute{"password"},
				},
			},
			password: "password",
			expected: optional.None[bool]()},
		{name: "UnknownPasswordAttribute",
			object: Object{
				bindPasswords: []string{"userPasswd"},
				attributes: map[string]yaldaplib.Attribute{
					"password": Attribute{"password"},
				},
			},
			password: "password",
			expected: optional.Some(false), // Authorisation configured but password not found -> wrong credential
		},
		{name: "EmptyPasswordAttribute",
			object: Object{
				bindPasswords: []string{"password"},
				attributes: map[string]yaldaplib.Attribute{
					"password": Attribute{},
				},
			},
			password: "password",
			expected: optional.Some(false)},
		{name: "WrongPasswordAttribute",
			object: Object{
				bindPasswords: []string{"password"},
				attributes: map[string]yaldaplib.Attribute{
					"password": Attribute{"password"},
				},
			},
			password: "not-password",
			expected: optional.Some(false)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.object.Bind(tt.password)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestObject_CanAccessTo(t *testing.T) {
	tests := []struct {
		name     string
		object   Object
		dn       string
		expected bool
	}{
		{name: "DeniedByDefault",
			object:   Object{},
			dn:       "uid=alice,ou=people",
			expected: false},
		{name: "DeniedByDefault2",
			object:   Object{acls: objectAclList{}},
			dn:       "uid=alice,ou=people",
			expected: false},
		{name: "AllowedOnDN",
			object:   Object{acls: objectAclList{{"uid=alice", true}}},
			dn:       "uid=alice",
			expected: true},
		{name: "AllowedOnParentDN",
			object:   Object{acls: objectAclList{{"ou=people", true}}},
			dn:       "uid=alice,ou=people",
			expected: true},
		{name: "DeniedOnDN",
			object:   Object{acls: objectAclList{{"uid=alice", false}}},
			dn:       "uid=alice",
			expected: false},
		{name: "DeniedOnParentDN",
			object:   Object{acls: objectAclList{{"ou=people", false}}},
			dn:       "uid=alice,ou=people",
			expected: false},

		{name: "AllowedOnParentDNButDeniedOnDN",
			object:   Object{acls: objectAclList{{"ou=people", true}, {"uid=alice,ou=people", false}}},
			dn:       "uid=alice,ou=people",
			expected: false},
		{name: "AllowedOnPParentDNButDeniedOnParentDN",
			object:   Object{acls: objectAclList{{"dc=org", true}, {"ou=people,dc=org", false}}},
			dn:       "uid=alice,ou=people,dc=org",
			expected: false},

		{name: "DeniedOnParentDNButAllowedOnDN",
			object:   Object{acls: objectAclList{{"ou=people", false}, {"uid=alice,ou=people", true}}},
			dn:       "uid=alice,ou=people",
			expected: true},
		{name: "DeniedOnPParentDNButAllowedOnParentDN",
			object:   Object{acls: objectAclList{{"dc=org", false}, {"ou=people,dc=org", true}}},
			dn:       "uid=alice,ou=people,dc=org",
			expected: true},

		{name: "DeniedOnParentWithAllowedFragment",
			object:   Object{acls: objectAclList{{"dc=org", false}, {"ou=people", true}}},
			dn:       "uid=alice,ou=people,dc=org",
			expected: false},

		{name: "DeniedOnParentWithAllowedFragment2",
			object:   Object{acls: objectAclList{{"dc=org", false}, {"ou=people", true}, {"uid=bob,ou=people,dc=org", false}, {"a=a,b=b,c=c,d=d,e=e", true}}},
			dn:       "uid=alice,ou=people,dc=org",
			expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sort.Sort(tt.object.acls) // NOTE: use the same sorting mechanism than during parsing

			result := tt.object.CanAccessTo(tt.dn)
			assert.Equal(t, tt.expected, result)
		})
	}
}
