package yamldir

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
	"gopkg.in/yaml.v3"
)

func TestParseDirectory(t *testing.T) {
	__ := func(entry object) *object {
		if entry.attributes == nil {
			entry.attributes = ldap.Attributes{}
		}
		if entry.children == nil {
			entry.children = map[string]*object{}
		}
		return &entry
	}

	tests := []struct {
		name   string
		yaml   string
		expect *object
		error
	}{
		{name: "Simple",
			yaml: `uid:alice: {}`,
			expect: __(object{
				children: map[string]*object{
					"uid=alice": __(object{dn: "uid=alice",
						attributes: ldap.Attributes{"uid": attribute{"alice"}},
					}),
				}}),
		},

		{name: "SimpleWithAttributes",
			yaml: `
uid:alice:
  .@memberOf: [admin, user, h4ck3r]
  .@givenname: alice
`,
			expect: __(object{
				children: map[string]*object{
					"uid=alice": __(object{dn: "uid=alice",
						attributes: ldap.Attributes{"uid": attribute{"alice"}, "memberOf": attribute{"admin", "user", "h4ck3r"}, "givenname": attribute{"alice"}},
					}),
				}}),
		},

		{name: "MultipleWithAttributes",
			yaml: `
uid:alice:
  .@memberOf: [admin, user, h4ck3r]
  .@givenname: alice

uid:bob:
  .@memberOf: [user]
  .@givenname: bob
`,
			expect: __(object{
				children: map[string]*object{
					"uid=alice": __(object{dn: "uid=alice",
						attributes: ldap.Attributes{"uid": attribute{"alice"}, "memberOf": attribute{"admin", "user", "h4ck3r"}, "givenname": attribute{"alice"}},
					}),
					"uid=bob": __(object{dn: "uid=bob",
						attributes: ldap.Attributes{"uid": attribute{"bob"}, "memberOf": attribute{"user"}, "givenname": attribute{"bob"}},
					}),
				}}),
		},

		{name: "SimpleNestedItem",
			yaml: `
dc:org:
  cn:example:
    ou:people:
      uid:alice:
        .@memberOf: [admin, user, h4ck3r]
        .@givenname: alice
`,
			expect: __(object{
				children: map[string]*object{
					"dc=org": __(object{dn: "dc=org",
						attributes: ldap.Attributes{"dc": attribute{"org"}},
						children: map[string]*object{
							"cn=example": __(object{dn: "cn=example,dc=org",
								attributes: ldap.Attributes{"cn": attribute{"example"}},
								children: map[string]*object{
									"ou=people": __(object{dn: "ou=people,cn=example,dc=org",
										attributes: ldap.Attributes{"ou": attribute{"people"}},
										children: map[string]*object{
											"uid=alice": __(object{dn: "uid=alice,ou=people,cn=example,dc=org",
												attributes: ldap.Attributes{"uid": attribute{"alice"}, "memberOf": attribute{"admin", "user", "h4ck3r"}, "givenname": attribute{"alice"}},
											}),
										},
									}),
								},
							}),
						},
					}),
				}}),
		},

		{name: "MultipleNestedItem",
			yaml: `
dc:org:
  cn:example:
    ou:people:
      uid:alice:
        .@memberOf: [admin, user, h4ck3r]
        .@givenname: alice
      uid:bob:
        .@memberOf: [user]
        .@givenname: bob
    ou:groups:
      cn:admin:
        .@members: 
        - uid=alice,ou=people,cn=example,dc=org
      cn:user:
        .@members: 
        - uid=alice,ou=people,cn=example,dc=org
        - uid=bob,ou=people,cn=example,dc=org
      cn:h4ck3r:
        .@members: 
        - uid=alice,ou=people,cn=example,dc=org
`,
			expect: __(object{
				children: map[string]*object{
					"dc=org": __(object{dn: "dc=org",
						attributes: ldap.Attributes{"dc": attribute{"org"}},
						children: map[string]*object{
							"cn=example": __(object{dn: "cn=example,dc=org",
								attributes: ldap.Attributes{"cn": attribute{"example"}},
								children: map[string]*object{
									"ou=people": __(object{dn: "ou=people,cn=example,dc=org",
										attributes: ldap.Attributes{"ou": attribute{"people"}},
										children: map[string]*object{
											"uid=alice": __(object{dn: "uid=alice,ou=people,cn=example,dc=org",
												attributes: ldap.Attributes{"uid": attribute{"alice"}, "memberOf": attribute{"admin", "user", "h4ck3r"}, "givenname": attribute{"alice"}},
											}),
											"uid=bob": __(object{dn: "uid=bob,ou=people,cn=example,dc=org",
												attributes: ldap.Attributes{"uid": attribute{"bob"}, "memberOf": attribute{"user"}, "givenname": attribute{"bob"}},
											}),
										},
									}),
									"ou=groups": __(object{dn: "ou=groups,cn=example,dc=org",
										attributes: ldap.Attributes{"ou": attribute{"groups"}},
										children: map[string]*object{
											"cn=admin": __(object{dn: "cn=admin,ou=groups,cn=example,dc=org",
												attributes: ldap.Attributes{"cn": attribute{"admin"}, "members": attribute{"uid=alice,ou=people,cn=example,dc=org"}},
											}),
											"cn=user": __(object{dn: "cn=user,ou=groups,cn=example,dc=org",
												attributes: ldap.Attributes{"cn": attribute{"user"}, "members": attribute{"uid=alice,ou=people,cn=example,dc=org", "uid=bob,ou=people,cn=example,dc=org"}},
											}),
											"cn=h4ck3r": __(object{dn: "cn=h4ck3r,ou=groups,cn=example,dc=org",
												attributes: ldap.Attributes{"cn": attribute{"h4ck3r"}, "members": attribute{"uid=alice,ou=people,cn=example,dc=org"}},
											}),
										},
									}),
								},
							}),
						},
					}),
				}}),
		},

		{name: "InvalidAttribute",
			yaml: `
uid:alice:
  .@attr: {}
`,
			error: fmt.Errorf("failed to get attribute on uid=alice: invalid attribute type 'map[string]interface {}' on attribute 'attr'")},
		{name: "InvalidSubObject",
			yaml: `
ou:people:
  uid:alice:
    boolean: true
`,
			error: fmt.Errorf("invalid field 'boolean' on uid=alice,ou=people: must be an object")},
		{name: "NoSubObjectType",
			yaml: `
ou:people:
  uid:alice:
    boolean: {}
`,
			error: fmt.Errorf("invalid field 'boolean' on uid=alice,ou=people: should contains the object type (ou, cn, ...)")},

		{name: "ValidPasswordBindProperty",
			yaml: `
ou:people:
  uid:alice:
    .#bindPassword: [password]
    .@password: alice
`,
			expect: __(object{
				children: map[string]*object{
					"ou=people": __(object{dn: "ou=people",
						attributes: map[string]ldap.Attribute{"ou": attribute{"people"}},
						children: map[string]*object{
							"uid=alice": __(object{dn: "uid=alice,ou=people",
								bindPasswords: []string{"password"},
								attributes: map[string]ldap.Attribute{
									"uid":      attribute{"alice"},
									"password": attribute{"alice"},
								},
							}),
						},
					}),
				},
			}),
		},
		{name: "ValidMultiPasswordBindProperty",
			yaml: `
ou:people:
  uid:alice:
    .#bindPassword: [password, userPasswd]
    .@password: alice
`,
			expect: __(object{
				children: map[string]*object{
					"ou=people": __(object{dn: "ou=people",
						attributes: map[string]ldap.Attribute{"ou": attribute{"people"}},
						children: map[string]*object{
							"uid=alice": __(object{dn: "uid=alice,ou=people",
								bindPasswords: []string{"password", "userPasswd"},
								attributes: map[string]ldap.Attribute{
									"uid":      attribute{"alice"},
									"password": attribute{"alice"},
								},
							}),
						},
					}),
				},
			}),
		},
		{name: "ValidEmptyPasswordBindProperty",
			yaml: `
ou:people:
  uid:alice:
    .#bindPassword: []
    .@password: alice
`,
			expect: __(object{
				children: map[string]*object{
					"ou=people": __(object{dn: "ou=people",
						attributes: map[string]ldap.Attribute{"ou": attribute{"people"}},
						children: map[string]*object{
							"uid=alice": __(object{dn: "uid=alice,ou=people",
								attributes: map[string]ldap.Attribute{
									"uid":      attribute{"alice"},
									"password": attribute{"alice"},
								},
							}),
						},
					}),
				},
			}),
		},

		{name: "ValidAllowedDNProperty",
			yaml: `
ou:people:
  uid:alice:
    .#allowDN: [ou=people, "ou=subgroup,dc=example,dc=org"]
    .@password: alice
`,
			expect: __(object{
				children: map[string]*object{
					"ou=people": __(object{dn: "ou=people",
						attributes: map[string]ldap.Attribute{"ou": attribute{"people"}},
						children: map[string]*object{
							"uid=alice": __(object{dn: "uid=alice,ou=people",
								acls: objectAclList{{"ou=subgroup,dc=example,dc=org", true}, {"ou=people", true}},
								attributes: map[string]ldap.Attribute{
									"uid":      attribute{"alice"},
									"password": attribute{"alice"},
								},
							}),
						},
					}),
				},
			}),
		},
		{name: "ValidDeniedDNProperty",
			yaml: `
ou:people:
  uid:alice:
    .#denyDN: [ou=people, "ou=subgroup,dc=example,dc=org"]
    .@password: alice
`,
			expect: __(object{
				children: map[string]*object{
					"ou=people": __(object{dn: "ou=people",
						attributes: map[string]ldap.Attribute{"ou": attribute{"people"}},
						children: map[string]*object{
							"uid=alice": __(object{dn: "uid=alice,ou=people",
								acls: objectAclList{{"ou=subgroup,dc=example,dc=org", false}, {"ou=people", false}},
								attributes: map[string]ldap.Attribute{
									"uid":      attribute{"alice"},
									"password": attribute{"alice"},
								},
							}),
						},
					}),
				},
			}),
		},
		{name: "ValidAllowedDeniedDNProperty",
			yaml: `
ou:people:
  uid:alice:
    .#allowDN: [ou=people]
    .#denyDN: ["uid=alice,ou=people"]
    .@password: alice
`,
			expect: __(object{
				children: map[string]*object{
					"ou=people": __(object{dn: "ou=people",
						attributes: map[string]ldap.Attribute{"ou": attribute{"people"}},
						children: map[string]*object{
							"uid=alice": __(object{dn: "uid=alice,ou=people",
								acls: objectAclList{{"uid=alice,ou=people", false}, {"ou=people", true}},
								attributes: map[string]ldap.Attribute{
									"uid":      attribute{"alice"},
									"password": attribute{"alice"},
								},
							}),
						},
					}),
				},
			}),
		},
		{name: "EmptyAllowedDeniedDNProperty",
			yaml: `
ou:people:
  uid:alice:
    .#allowDN: []
    .#denyDN: []
    .@password: alice
`,
			expect: __(object{
				children: map[string]*object{
					"ou=people": __(object{dn: "ou=people",
						attributes: map[string]ldap.Attribute{"ou": attribute{"people"}},
						children: map[string]*object{
							"uid=alice": __(object{dn: "uid=alice,ou=people",
								attributes: map[string]ldap.Attribute{
									"uid":      attribute{"alice"},
									"password": attribute{"alice"},
								},
							}),
						},
					}),
				},
			}),
		},
		{name: "ObjectClassProperty",
			yaml: `
ou:people:
  uid:alice:
    .#objectClass: posixAccount
`,
			expect: __(object{
				children: map[string]*object{
					"ou=people": __(object{dn: "ou=people",
						attributes: map[string]ldap.Attribute{"ou": attribute{"people"}},
						children: map[string]*object{
							"uid=alice": __(object{dn: "uid=alice,ou=people",
								attributes: map[string]ldap.Attribute{
									"uid":         attribute{"alice"},
									"objectClass": attribute{"posixAccount"},
								},
							}),
						},
					}),
				},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var obj map[string]interface{}
			require.NoError(t, yaml.Unmarshal([]byte(tt.yaml), &obj))

			entry, err := parseObject("", obj, map[string]*object{})

			if tt.error != nil {
				assert.EqualError(t, err, tt.error.Error())
			} else {
				require.NoError(t, err)

				assert.Equal(t, tt.expect, entry)
			}
		})
	}
}

func TestParseAttribute(t *testing.T) {
	tests := []struct {
		name   string
		obj    interface{}
		expect attribute
		error
	}{
		{name: "String",
			obj:    "attr1",
			expect: attribute{"attr1"}},
		{name: "Integer",
			obj:    3,
			expect: attribute{"3"}},
		{name: "Boolean",
			obj:    false,
			expect: attribute{"false"}},
		{name: "StringArray",
			obj:    []string{"attr1", "attr2"},
			expect: attribute{"attr1", "attr2"}},
		{name: "MixedArray",
			obj:    []interface{}{"attr1", 3, false},
			expect: attribute{"attr1", "3", "false"}},

		{name: "InvalidAttribute",
			error: fmt.Errorf("invalid attribute type '<nil>' on attribute 'InvalidAttribute'")},
		{name: "InvalidAttribute2",
			obj:   map[string]string{},
			error: fmt.Errorf("invalid attribute type 'map[string]string' on attribute 'InvalidAttribute2'")},
		{name: "InvalidMixedArray",
			obj:   []interface{}{"attr1", 3, false, nil},
			error: fmt.Errorf("invalid attribute type '<nil>' on attribute 'InvalidMixedArray[3]'")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr, err := parseAttributeValue(tt.name, tt.obj)

			if tt.error != nil {
				assert.EqualError(t, err, tt.error.Error())
			} else {
				require.NoError(t, err)
				assert.ElementsMatch(t, tt.expect, attr)
			}
		})
	}
}
