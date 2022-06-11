package yaml

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
	"gopkg.in/yaml.v3"
)

func TestParseEntry(t *testing.T) {
	__ := func(entry Object) *Object {
		if entry.attributes == nil {
			entry.attributes = yaldaplib.Attributes{}
		}
		if entry.children == nil {
			entry.children = map[string]*Object{}
		}
		return &entry
	}

	tests := []struct {
		name   string
		yaml   string
		expect *Object
		error
	}{
		{name: "SimpleEntry",
			yaml: `uid:alice: {}`,
			expect: __(Object{
				children: map[string]*Object{
					"uid=alice": __(Object{dn: "uid=alice",
						attributes: yaldaplib.Attributes{"uid": &Attribute{"alice"}},
					}),
				}}),
		},

		{name: "SimpleEntryWithAttributes",
			yaml: `
uid:alice:
  .@memberOf: [admin, user, h4ck3r]
  .@givenname: alice
`,
			expect: __(Object{
				children: map[string]*Object{
					"uid=alice": __(Object{dn: "uid=alice",
						attributes: yaldaplib.Attributes{"uid": &Attribute{"alice"}, "memberOf": &Attribute{"admin", "user", "h4ck3r"}, "givenname": &Attribute{"alice"}},
					}),
				}}),
		},

		{name: "MultipleEntryWithAttributes",
			yaml: `
uid:alice:
  .@memberOf: [admin, user, h4ck3r]
  .@givenname: alice

uid:bob:
  .@memberOf: [user]
  .@givenname: bob
`,
			expect: __(Object{
				children: map[string]*Object{
					"uid=alice": __(Object{dn: "uid=alice",
						attributes: yaldaplib.Attributes{"uid": &Attribute{"alice"}, "memberOf": &Attribute{"admin", "user", "h4ck3r"}, "givenname": &Attribute{"alice"}},
					}),
					"uid=bob": __(Object{dn: "uid=bob",
						attributes: yaldaplib.Attributes{"uid": &Attribute{"bob"}, "memberOf": &Attribute{"user"}, "givenname": &Attribute{"bob"}},
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
			expect: __(Object{
				children: map[string]*Object{
					"dc=org": __(Object{dn: "dc=org",
						attributes: yaldaplib.Attributes{"dc": &Attribute{"org"}},
						children: map[string]*Object{
							"cn=example": __(Object{dn: "cn=example,dc=org",
								attributes: yaldaplib.Attributes{"cn": &Attribute{"example"}},
								children: map[string]*Object{
									"ou=people": __(Object{dn: "ou=people,cn=example,dc=org",
										attributes: yaldaplib.Attributes{"ou": &Attribute{"people"}},
										children: map[string]*Object{
											"uid=alice": __(Object{dn: "uid=alice,ou=people,cn=example,dc=org",
												attributes: yaldaplib.Attributes{"uid": &Attribute{"alice"}, "memberOf": &Attribute{"admin", "user", "h4ck3r"}, "givenname": &Attribute{"alice"}},
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
			expect: __(Object{
				children: map[string]*Object{
					"dc=org": __(Object{dn: "dc=org",
						attributes: yaldaplib.Attributes{"dc": &Attribute{"org"}},
						children: map[string]*Object{
							"cn=example": __(Object{dn: "cn=example,dc=org",
								attributes: yaldaplib.Attributes{"cn": &Attribute{"example"}},
								children: map[string]*Object{
									"ou=people": __(Object{dn: "ou=people,cn=example,dc=org",
										attributes: yaldaplib.Attributes{"ou": &Attribute{"people"}},
										children: map[string]*Object{
											"uid=alice": __(Object{dn: "uid=alice,ou=people,cn=example,dc=org",
												attributes: yaldaplib.Attributes{"uid": &Attribute{"alice"}, "memberOf": &Attribute{"admin", "user", "h4ck3r"}, "givenname": &Attribute{"alice"}},
											}),
											"uid=bob": __(Object{dn: "uid=bob,ou=people,cn=example,dc=org",
												attributes: yaldaplib.Attributes{"uid": &Attribute{"bob"}, "memberOf": &Attribute{"user"}, "givenname": &Attribute{"bob"}},
											}),
										},
									}),
									"ou=groups": __(Object{dn: "ou=groups,cn=example,dc=org",
										attributes: yaldaplib.Attributes{"ou": &Attribute{"groups"}},
										children: map[string]*Object{
											"cn=admin": __(Object{dn: "cn=admin,ou=groups,cn=example,dc=org",
												attributes: yaldaplib.Attributes{"cn": &Attribute{"admin"}, "members": &Attribute{"uid=alice,ou=people,cn=example,dc=org"}},
											}),
											"cn=user": __(Object{dn: "cn=user,ou=groups,cn=example,dc=org",
												attributes: yaldaplib.Attributes{"cn": &Attribute{"user"}, "members": &Attribute{"uid=alice,ou=people,cn=example,dc=org", "uid=bob,ou=people,cn=example,dc=org"}},
											}),
											"cn=h4ck3r": __(Object{dn: "cn=h4ck3r,ou=groups,cn=example,dc=org",
												attributes: yaldaplib.Attributes{"cn": &Attribute{"h4ck3r"}, "members": &Attribute{"uid=alice,ou=people,cn=example,dc=org"}},
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
    .#BindPasswordAttr: [password]
    .@password: alice
`,
			expect: __(Object{
				children: map[string]*Object{
					"ou=people": __(Object{dn: "ou=people",
						attributes: map[string]yaldaplib.Attribute{"ou": &Attribute{"people"}},
						children: map[string]*Object{
							"uid=alice": __(Object{dn: "uid=alice,ou=people",
								bindPasswords: []string{"password"},
								attributes: map[string]yaldaplib.Attribute{
									"uid":      &Attribute{"alice"},
									"password": &Attribute{"alice"},
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
    .#BindPasswordAttr: [password, userPasswd]
    .@password: alice
`,
			expect: __(Object{
				children: map[string]*Object{
					"ou=people": __(Object{dn: "ou=people",
						attributes: map[string]yaldaplib.Attribute{"ou": &Attribute{"people"}},
						children: map[string]*Object{
							"uid=alice": __(Object{dn: "uid=alice,ou=people",
								bindPasswords: []string{"password", "userPasswd"},
								attributes: map[string]yaldaplib.Attribute{
									"uid":      &Attribute{"alice"},
									"password": &Attribute{"alice"},
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
    .#BindPasswordAttr: []
    .@password: alice
`,
			expect: __(Object{
				children: map[string]*Object{
					"ou=people": __(Object{dn: "ou=people",
						attributes: map[string]yaldaplib.Attribute{"ou": &Attribute{"people"}},
						children: map[string]*Object{
							"uid=alice": __(Object{dn: "uid=alice,ou=people",
								attributes: map[string]yaldaplib.Attribute{
									"uid":      &Attribute{"alice"},
									"password": &Attribute{"alice"},
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
    .#AllowedDN: [ou=people, "ou=subgroup,dc=example,dc=org"]
    .@password: alice
`,
			expect: __(Object{
				children: map[string]*Object{
					"ou=people": __(Object{dn: "ou=people",
						attributes: map[string]yaldaplib.Attribute{"ou": &Attribute{"people"}},
						children: map[string]*Object{
							"uid=alice": __(Object{dn: "uid=alice,ou=people",
								acls: objectAclList{{"ou=subgroup,dc=example,dc=org", true}, {"ou=people", true}},
								attributes: map[string]yaldaplib.Attribute{
									"uid":      &Attribute{"alice"},
									"password": &Attribute{"alice"},
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
    .#DeniedDN: [ou=people, "ou=subgroup,dc=example,dc=org"]
    .@password: alice
`,
			expect: __(Object{
				children: map[string]*Object{
					"ou=people": __(Object{dn: "ou=people",
						attributes: map[string]yaldaplib.Attribute{"ou": &Attribute{"people"}},
						children: map[string]*Object{
							"uid=alice": __(Object{dn: "uid=alice,ou=people",
								acls: objectAclList{{"ou=subgroup,dc=example,dc=org", false}, {"ou=people", false}},
								attributes: map[string]yaldaplib.Attribute{
									"uid":      &Attribute{"alice"},
									"password": &Attribute{"alice"},
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
    .#AllowedDN: [ou=people]
    .#DeniedDN: ["uid=alice,ou=people"]
    .@password: alice
`,
			expect: __(Object{
				children: map[string]*Object{
					"ou=people": __(Object{dn: "ou=people",
						attributes: map[string]yaldaplib.Attribute{"ou": &Attribute{"people"}},
						children: map[string]*Object{
							"uid=alice": __(Object{dn: "uid=alice,ou=people",
								acls: objectAclList{{"uid=alice,ou=people", false}, {"ou=people", true}},
								attributes: map[string]yaldaplib.Attribute{
									"uid":      &Attribute{"alice"},
									"password": &Attribute{"alice"},
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
    .#AllowedDN: []
    .#DeniedDN: []
    .@password: alice
`,
			expect: __(Object{
				children: map[string]*Object{
					"ou=people": __(Object{dn: "ou=people",
						attributes: map[string]yaldaplib.Attribute{"ou": &Attribute{"people"}},
						children: map[string]*Object{
							"uid=alice": __(Object{dn: "uid=alice,ou=people",
								attributes: map[string]yaldaplib.Attribute{
									"uid":      &Attribute{"alice"},
									"password": &Attribute{"alice"},
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

			entry, err := parseObject("", obj, map[string]*Object{})

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
		expect Attribute
		error
	}{
		{name: "String",
			obj:    "attr1",
			expect: Attribute{"attr1"}},
		{name: "Integer",
			obj:    3,
			expect: Attribute{"3"}},
		{name: "Boolean",
			obj:    false,
			expect: Attribute{"false"}},
		{name: "StringArray",
			obj:    []string{"attr1", "attr2"},
			expect: Attribute{"attr1", "attr2"}},
		{name: "MixedArray",
			obj:    []interface{}{"attr1", 3, false},
			expect: Attribute{"attr1", "3", "false"}},

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
				assert.ElementsMatch(t, tt.expect, *attr)
			}
		})
	}
}
