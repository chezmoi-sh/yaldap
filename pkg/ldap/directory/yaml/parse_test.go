package yamldir

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
	"github.com/xunleii/yaldap/pkg/ldap/directory/common"
	"gopkg.in/yaml.v3"
)

func TestParseLDAPObject_Basic(t *testing.T) {
	raw := "uid:alice: {}"
	expect := map[string]*common.Object{
		"uid:alice": {
			ImplObject: common.ImplObject{
				DN:         "uid=alice,go=test",
				Attributes: ldap.Attributes{"uid": []string{"alice"}},
				SubObjects: map[string]*common.Object{},
			},
		},
	}

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{ImplObject: common.ImplObject{SubObjects: map[string]*common.Object{}}}
	err = parseLDAPObject(obj, "go:test", node.Content[0])
	assert.NoError(t, err)
	assert.Equal(t, expect, obj.SubObjects["go:test"].SubObjects)
}

func TestParseLDAPObject_WithAttributes(t *testing.T) {
	raw := `
ou:people:
  uid:alice:
    memberOf: [admin, user, h4ck3r]
    givenname: alice
{toto: true}: ok
`
	expect := map[string]*common.Object{
		"ou:people": {
			ImplObject: common.ImplObject{
				DN:         "ou=people,go=test",
				Attributes: ldap.Attributes{"ou": []string{"people"}},
				SubObjects: map[string]*common.Object{
					"uid:alice": {
						ImplObject: common.ImplObject{
							DN: "uid=alice,ou=people,go=test",
							Attributes: ldap.Attributes{
								"uid":       []string{"alice"},
								"memberOf":  []string{"admin", "user", "h4ck3r"},
								"givenname": []string{"alice"},
							},
							SubObjects: map[string]*common.Object{},
						},
					},
				},
			},
		},
	}

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{ImplObject: common.ImplObject{SubObjects: map[string]*common.Object{}}}
	err = parseLDAPObject(obj, "go:test", node.Content[0])
	assert.NoError(t, err)
	assert.Equal(t, expect, obj.SubObjects["go:test"].SubObjects)
}

func TestParseLDAPObject_WithAliasNode(t *testing.T) {
	raw := `
ou:people:
  uid:alice: &alice
    memberOf: [admin, user, h4ck3r]
    givenname: alice
  uid:bob: *alice
`
	expect := map[string]*common.Object{
		"ou:people": {
			ImplObject: common.ImplObject{
				DN:         "ou=people,go=test",
				Attributes: ldap.Attributes{"ou": []string{"people"}},
				SubObjects: map[string]*common.Object{
					"uid:alice": {
						ImplObject: common.ImplObject{
							DN: "uid=alice,ou=people,go=test",
							Attributes: ldap.Attributes{
								"uid":       []string{"alice"},
								"memberOf":  []string{"admin", "user", "h4ck3r"},
								"givenname": []string{"alice"},
							},
							SubObjects: map[string]*common.Object{},
						},
					},
					"uid:bob": {
						ImplObject: common.ImplObject{
							DN: "uid=bob,ou=people,go=test",
							Attributes: ldap.Attributes{
								"uid":       []string{"bob"},
								"memberOf":  []string{"admin", "user", "h4ck3r"},
								"givenname": []string{"alice"},
							},
							SubObjects: map[string]*common.Object{},
						},
					},
				},
			},
		},
	}

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{ImplObject: common.ImplObject{SubObjects: map[string]*common.Object{}}}
	err = parseLDAPObject(obj, "go:test", node.Content[0])
	assert.NoError(t, err)
	assert.Equal(t, expect, obj.SubObjects["go:test"].SubObjects)
}

func TestParseLDAPObject_WithMergeField(t *testing.T) {
	raw := `
ou:people:
  uid:alice: &alice
    objectclass: [posixAccount]
    memberOf: [admin, user, h4ck3r]
    givenname: alice
  uid:bob:
    <<: *alice
    objectclass: [UserMail]
    givenname: bob
`
	expect := map[string]*common.Object{
		"ou:people": {
			ImplObject: common.ImplObject{
				DN:         "ou=people,go=test",
				Attributes: ldap.Attributes{"ou": []string{"people"}},
				SubObjects: map[string]*common.Object{
					"uid:alice": {
						ImplObject: common.ImplObject{
							DN: "uid=alice,ou=people,go=test",
							Attributes: ldap.Attributes{
								"uid":         []string{"alice"},
								"objectclass": []string{"posixAccount"},
								"memberOf":    []string{"admin", "user", "h4ck3r"},
								"givenname":   []string{"alice"},
							},
							SubObjects: map[string]*common.Object{},
						},
					},
					"uid:bob": {
						ImplObject: common.ImplObject{
							DN: "uid=bob,ou=people,go=test",
							Attributes: ldap.Attributes{
								"uid":         []string{"bob"},
								"objectclass": []string{"UserMail"},
								"memberOf":    []string{"admin", "user", "h4ck3r"},
								"givenname":   []string{"bob"},
							},
							SubObjects: map[string]*common.Object{},
						},
					},
				},
			},
		},
	}

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{ImplObject: common.ImplObject{SubObjects: map[string]*common.Object{}}}
	err = parseLDAPObject(obj, "go:test", node.Content[0])
	assert.NoError(t, err)
	assert.Equal(t, expect, obj.SubObjects["go:test"].SubObjects)
}

func TestParseLDAPObject_WithInvalidKey(t *testing.T) {
	raw := "alice: {}"
	expectErr := "invalid LDAP YAML document at line 1, column 8: invalid key: 'alice' must be in the form '<type>:<name>' (e.g. 'ou:users')"

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{ImplObject: common.ImplObject{SubObjects: map[string]*common.Object{}}}
	err = parseLDAPObject(obj, "go:test", node.Content[0])
	assert.EqualError(t, err, expectErr)
}

func TestParseLDAPObject_WithInvalidMergeNode(t *testing.T) {
	raw := `
ou:people:
  uid:alice: &alice scalar
  uid:bob:
    <<: *alice
`
	expectErr := "invalid LDAP YAML document at line 5, column 5: only mapping nodes can be merged, got a scalar node (aka. primitive)"

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{ImplObject: common.ImplObject{SubObjects: map[string]*common.Object{}}}
	err = parseLDAPObject(obj, "go:test", node.Content[0])
	assert.EqualError(t, err, expectErr)
}

func TestParseLDAPAttribute_Basic(t *testing.T) {
	raw := "uid: alice"
	expect := &common.Object{
		ImplObject: common.ImplObject{
			DN:         "",
			Attributes: ldap.Attributes{"uid": []string{"alice"}},
		},
	}

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{}
	err = parseLDAPAttribute(obj, node.Content[0].Content[0].Value, node.Content[0].Content[1])
	assert.NoError(t, err)
	assert.Equal(t, expect, obj)
}

func TestParseLDAPAttribute_WithNullValue(t *testing.T) {
	raw := "uid: null"
	expect := &common.Object{
		ImplObject: common.ImplObject{
			DN: "",
		},
	}

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{}
	err = parseLDAPAttribute(obj, node.Content[0].Content[0].Value, node.Content[0].Content[1])
	assert.NoError(t, err)
	assert.Equal(t, expect, obj)
}

func TestParseLDAPAttribute_WithBindPassword(t *testing.T) {
	raw := "password: !<tag:yaml.org,2002:ldap/bind:password> alice"
	expect := &common.Object{
		ImplObject: common.ImplObject{
			DN:            "",
			BindPasswords: []string{"alice"},
			Attributes: ldap.Attributes{
				"password": []string{"alice"},
			},
		},
	}

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{}
	err = parseLDAPAttribute(obj, node.Content[0].Content[0].Value, node.Content[0].Content[1])
	assert.NoError(t, err)
	assert.Equal(t, expect, obj)
}

func TestParseLDAPAttribute_WithAllowedOn(t *testing.T) {
	raw := "allowedOn: !<tag:yaml.org,2002:ldap/acl:allow-on> ou=subgroup,dc=example,dc=org"
	expect := &common.Object{
		ImplObject: common.ImplObject{
			DN: "",
			ACLs: common.ACLRuleSet{
				{DistinguishedNameSuffix: "ou=subgroup,dc=example,dc=org", Allowed: true},
			},
		},
	}

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{}
	err = parseLDAPAttribute(obj, node.Content[0].Content[0].Value, node.Content[0].Content[1])
	assert.NoError(t, err)
	assert.Equal(t, expect, obj)
}

func TestParseLDAPAttribute_WithMultipleAllowedOn(t *testing.T) {
	raw := "allowedOn: !<tag:yaml.org,2002:ldap/acl:allow-on> [\"ou=subgroup,dc=example,dc=org\", \"ou=othergroup,dc=example,dc=org\"]"
	expect := &common.Object{
		ImplObject: common.ImplObject{
			DN: "",
			ACLs: common.ACLRuleSet{
				{DistinguishedNameSuffix: "ou=othergroup,dc=example,dc=org", Allowed: true},
				{DistinguishedNameSuffix: "ou=subgroup,dc=example,dc=org", Allowed: true},
			},
		},
	}

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{}
	err = parseLDAPAttribute(obj, node.Content[0].Content[0].Value, node.Content[0].Content[1])
	assert.NoError(t, err)
	assert.Equal(t, expect, obj)
}

func TestParseLDAPAttribute_WithDeniedOn(t *testing.T) {
	raw := "deniedOn: !<tag:yaml.org,2002:ldap/acl:deny-on> ou=subgroup,dc=example,dc=org"
	expect := &common.Object{
		ImplObject: common.ImplObject{
			DN: "",
			ACLs: common.ACLRuleSet{
				{DistinguishedNameSuffix: "ou=subgroup,dc=example,dc=org", Allowed: false},
			},
		},
	}

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{}
	err = parseLDAPAttribute(obj, node.Content[0].Content[0].Value, node.Content[0].Content[1])
	assert.NoError(t, err)
	assert.Equal(t, expect, obj)
}

func TestParseLDAPAttribute_WithMultipleDeniedOn(t *testing.T) {
	raw := "deniedOn: !<tag:yaml.org,2002:ldap/acl:deny-on> [\"ou=subgroup,dc=example,dc=org\", \"ou=othergroup,dc=example,dc=org\"]"
	expect := &common.Object{
		ImplObject: common.ImplObject{
			DN: "",
			ACLs: common.ACLRuleSet{
				{DistinguishedNameSuffix: "ou=othergroup,dc=example,dc=org", Allowed: false},
				{DistinguishedNameSuffix: "ou=subgroup,dc=example,dc=org", Allowed: false},
			},
		},
	}

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{}
	err = parseLDAPAttribute(obj, node.Content[0].Content[0].Value, node.Content[0].Content[1])
	assert.NoError(t, err)
	assert.Equal(t, expect, obj)
}

func TestParseLDAPAttribute_WithMixedTags(t *testing.T) {
	raw := `
authz:
  - !<tag:yaml.org,2002:ldap/bind:password> alice
  - !<tag:yaml.org,2002:ldap/acl:allow-on> ou=subgroup,dc=example,dc=org
  - !<tag:yaml.org,2002:ldap/acl:deny-on> ou=othergroup,dc=example,dc=org
  - other value
`
	expect := &common.Object{
		ImplObject: common.ImplObject{
			DN: "",
			ACLs: common.ACLRuleSet{
				{DistinguishedNameSuffix: "ou=othergroup,dc=example,dc=org", Allowed: false},
				{DistinguishedNameSuffix: "ou=subgroup,dc=example,dc=org", Allowed: true},
			},
			Attributes: ldap.Attributes{
				"authz": []string{"alice", "other value"},
			},
			BindPasswords: []string{"alice"},
		},
	}

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{}
	err = parseLDAPAttribute(obj, node.Content[0].Content[0].Value, node.Content[0].Content[1])
	assert.NoError(t, err)
	assert.Equal(t, expect, obj)
}

func TestParseLDAPAttribute_WithInvalidSequence(t *testing.T) {
	raw := `
invalid:
  - scalar
  - mapping: {}
`
	expectErr := "invalid LDAP YAML document at line 4, column 5: invalid attribute type: only a scalar node (aka. primitive) or a sequence node (aka. list/array) is allowed"

	var node yaml.Node
	err := yaml.Unmarshal([]byte(raw), &node)
	require.NoError(t, err)

	obj := &common.Object{}
	err = parseLDAPAttribute(obj, node.Content[0].Content[0].Value, node.Content[0].Content[1])
	assert.EqualError(t, err, expectErr)
}
