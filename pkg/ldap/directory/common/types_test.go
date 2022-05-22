package common

import (
	"testing"

	"github.com/jimlambrt/gldap"
	"github.com/stretchr/testify/assert"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
)

func TestObjectDN(t *testing.T) {
	obj := Object{
		ImplObject: ImplObject{
			DN: "cn=alice,ou=users,dc=example,dc=com",
		},
	}

	expectedDN := "cn=alice,ou=users,dc=example,dc=com"
	actualDN := obj.DN()

	assert.Equal(t, expectedDN, actualDN)
}

func TestObjectAttributes(t *testing.T) {
	obj := Object{
		ImplObject: ImplObject{
			Attributes: ldap.Attributes{
				"cn": []string{"Alice"},
				"sn": []string{"Smith"},
			},
		},
	}

	expectedAttributes := ldap.Attributes{
		"cn": []string{"Alice"},
		"sn": []string{"Smith"},
	}
	actualAttributes := obj.Attributes()

	assert.Equal(t, expectedAttributes, actualAttributes)
}

func TestObjectSearch(t *testing.T) {
	obj := Object{
		ImplObject: ImplObject{
			DN: "dc=example,dc=com",
			SubObjects: map[string]*Object{
				"ou=groups,dc=example,dc=com": {
					ImplObject: ImplObject{
						DN: "ou=groups,dc=example,dc=com",
						Attributes: ldap.Attributes{
							"ou": []string{"groups"},
						},
						SubObjects: map[string]*Object{
							"cn=developers,ou=groups,dc=example,dc=com": {
								ImplObject: ImplObject{
									DN: "cn=developers,ou=groups,dc=example,dc=com",
									Attributes: ldap.Attributes{
										"cn": []string{"developers"},
										"member": []string{
											"cn=alice,ou=users,dc=example,dc=com",
											"cn=bob,ou=users,dc=example,dc=com",
										},
									},
								},
							},
							"cn=testers,ou=groups,dc=example,dc=com": {
								ImplObject: ImplObject{
									DN: "cn=testers,ou=groups,dc=example,dc=com",
									Attributes: ldap.Attributes{
										"cn": []string{"testers"},
										"member": []string{
											"cn=alice,ou=users,dc=example,dc=com",
										},
									},
								},
							},
						},
					},
				},
				"ou=users,dc=example,dc=com": {
					ImplObject: ImplObject{
						DN: "ou=users,dc=example,dc=com",
						Attributes: ldap.Attributes{
							"ou": []string{"users"},
						},
						SubObjects: map[string]*Object{
							"cn=alice,ou=users,dc=example,dc=com": {
								ImplObject: ImplObject{
									DN: "cn=alice,ou=users,dc=example,dc=com",
									Attributes: ldap.Attributes{
										"cn": []string{"Alice"},
										"sn": []string{"Smith"},
										"memberOf": []string{
											"cn=developers,ou=groups,dc=example,dc=com",
											"cn=testers,ou=groups,dc=example,dc=com",
										},
									},
								},
							},
							"cn=bob,ou=users,dc=example,dc=com": {
								ImplObject: ImplObject{
									DN: "cn=bob,ou=users,dc=example,dc=com",
									Attributes: ldap.Attributes{
										"cn": []string{"Bob"},
										"sn": []string{"Johnson"},
										"memberOf": []string{
											"cn=developers,ou=groups,dc=example,dc=com",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	t.Run("Test search with invalid filter", func(t *testing.T) {
		scope := gldap.BaseObject
		filter := "invalid filter"
		var expectedObjects []ldap.Object
		actualObjects, err := obj.Search(scope, filter)

		assert.Error(t, err)
		assert.Equal(t, expectedObjects, actualObjects)
	})

	t.Run("Test search with BaseObject scope", func(t *testing.T) {
		scope := gldap.BaseObject
		filter := "(ou=users)"
		var expectedObjects []ldap.Object
		actualObjects, err := obj.Search(scope, filter)

		assert.NoError(t, err)
		assert.Equal(t, expectedObjects, actualObjects)
	})

	t.Run("Test search with SingleLevel scope", func(t *testing.T) {
		scope := gldap.SingleLevel
		filter := "(ou=users)"
		expectedObjects := []ldap.Object{
			&Object{
				ImplObject: ImplObject{
					DN: "ou=users,dc=example,dc=com",
					Attributes: ldap.Attributes{
						"ou": []string{"users"},
					},
					SubObjects: map[string]*Object{
						"cn=alice,ou=users,dc=example,dc=com": {
							ImplObject: ImplObject{
								DN: "cn=alice,ou=users,dc=example,dc=com",
								Attributes: ldap.Attributes{
									"cn": []string{"Alice"},
									"sn": []string{"Smith"},
									"memberOf": []string{
										"cn=developers,ou=groups,dc=example,dc=com",
										"cn=testers,ou=groups,dc=example,dc=com",
									},
								},
							},
						},
						"cn=bob,ou=users,dc=example,dc=com": {
							ImplObject: ImplObject{
								DN: "cn=bob,ou=users,dc=example,dc=com",
								Attributes: ldap.Attributes{
									"cn": []string{"Bob"},
									"sn": []string{"Johnson"},
									"memberOf": []string{
										"cn=developers,ou=groups,dc=example,dc=com",
									},
								},
							},
						},
					},
				},
			},
		}
		actualObjects, err := obj.Search(scope, filter)

		assert.NoError(t, err)
		assert.Equal(t, expectedObjects, actualObjects)
	})

	t.Run("Test search with WholeSubtree scope", func(t *testing.T) {
		scope := gldap.WholeSubtree
		filter := "(sn=Smith)"
		expectedObjects := []ldap.Object{
			&Object{
				ImplObject: ImplObject{
					DN: "cn=alice,ou=users,dc=example,dc=com",
					Attributes: ldap.Attributes{
						"cn": []string{"Alice"},
						"sn": []string{"Smith"},
						"memberOf": []string{
							"cn=developers,ou=groups,dc=example,dc=com",
							"cn=testers,ou=groups,dc=example,dc=com",
						},
					},
				},
			},
		}
		actualObjects, err := obj.Search(scope, filter)

		assert.NoError(t, err)
		assert.Equal(t, expectedObjects, actualObjects)
	})
}

func TestObjectBind(t *testing.T) {
	obj := Object{
		ImplObject: ImplObject{
			BindPasswords: []string{"password123", "pass123"},
		},
	}

	// Test with correct password
	password := "password123"
	expectedResult := true
	actualResult := obj.Bind(password)

	assert.Equal(t, expectedResult, actualResult)

	// Test with incorrect password
	password = "wrongpassword"
	expectedResult = false
	actualResult = obj.Bind(password)

	assert.Equal(t, expectedResult, actualResult)

	// Test with no bind passwords
	obj.BindPasswords = nil
	password = "password123"
	expectedResult = false
	actualResult = obj.Bind(password)

	assert.Equal(t, expectedResult, actualResult)
}

func TestObjectCanSearchOn(t *testing.T) {
	obj := Object{
		ImplObject: ImplObject{
			ACLs: ACLRuleSet{
				ACLRule{
					DistinguishedNameSuffix: "ou=users,dc=example,dc=com",
					Allowed:                 true,
				},
				ACLRule{
					DistinguishedNameSuffix: "dc=example,dc=com",
					Allowed:                 false,
				},
			},
		},
	}

	t.Run("Test with allowed DN", func(t *testing.T) {
		dn := "cn=alice,ou=users,dc=example,dc=com"
		expectedResult := true
		actualResult := obj.CanSearchOn(dn)

		assert.Equal(t, expectedResult, actualResult)
	})

	t.Run("Test with disallowed DN", func(t *testing.T) {
		dn := "cn=alice,dc=example,dc=com"
		expectedResult := false
		actualResult := obj.CanSearchOn(dn)

		assert.Equal(t, expectedResult, actualResult)
	})

	t.Run("Test with no matching ACLs", func(t *testing.T) {
		dn := "dc=com"
		expectedResult := false
		actualResult := obj.CanSearchOn(dn)

		assert.Equal(t, expectedResult, actualResult)
	})
}

func TestImplObjectAddAttribute(t *testing.T) {
	obj := ImplObject{}

	t.Run("Test adding attribute with values", func(t *testing.T) {
		name := "cn"
		values := []string{"Alice", "Bob"}
		obj.AddAttribute(name, values...)

		expectedAttributes := ldap.Attributes{
			"cn": []string{"Alice", "Bob"},
		}
		actualAttributes := obj.Attributes

		assert.Equal(t, expectedAttributes, actualAttributes)
	})

	t.Run("Test adding values to existing attribute", func(t *testing.T) {
		name := "cn"
		values := []string{"Charlie"}
		obj.AddAttribute(name, values...)

		expectedAttributes := ldap.Attributes{
			"cn": []string{"Alice", "Bob", "Charlie"},
		}
		actualAttributes := obj.Attributes

		assert.Equal(t, expectedAttributes, actualAttributes)
	})

	t.Run("Test adding attribute without values", func(t *testing.T) {
		name := "sn"
		obj.AddAttribute(name)

		expectedAttributes := ldap.Attributes{
			"cn": []string{"Alice", "Bob", "Charlie"},
			"sn": nil,
		}
		actualAttributes := obj.Attributes

		assert.Equal(t, expectedAttributes, actualAttributes)
	})
}

func TestImplObjectAddACLRule(t *testing.T) {
	obj := ImplObject{}

	t.Run("Test adding ACL rule", func(t *testing.T) {
		obj.AddACLRule(ACLRule{
			DistinguishedNameSuffix: "ou=users,dc=example,dc=com",
			Allowed:                 true,
		})

		expectedACLs := ACLRuleSet{
			ACLRule{
				DistinguishedNameSuffix: "ou=users,dc=example,dc=com",
				Allowed:                 true,
			},
		}
		actualACLs := obj.ACLs

		assert.Equal(t, expectedACLs, actualACLs)
	})

	// Test adding multiple ACL rules
	t.Run("Test adding multiple ACL rules", func(t *testing.T) {
		obj.AddACLRule(
			ACLRule{
				DistinguishedNameSuffix: "cn=alice,ou=users,dc=example,dc=com",
				Allowed:                 true,
			},
			ACLRule{
				DistinguishedNameSuffix: "dc=example,dc=com",
				Allowed:                 false,
			},
			ACLRule{
				DistinguishedNameSuffix: "dc=example,dc=com",
				Allowed:                 true,
			},
			ACLRule{
				DistinguishedNameSuffix: "dc=not-example,dc=com",
				Allowed:                 true,
			},
		)

		expectedACLs := ACLRuleSet{
			ACLRule{
				DistinguishedNameSuffix: "cn=alice,ou=users,dc=example,dc=com",
				Allowed:                 true,
			},
			ACLRule{
				DistinguishedNameSuffix: "ou=users,dc=example,dc=com",
				Allowed:                 true,
			},
			ACLRule{
				DistinguishedNameSuffix: "dc=example,dc=com",
				Allowed:                 false,
			},
			ACLRule{
				DistinguishedNameSuffix: "dc=example,dc=com",
				Allowed:                 true,
			},
			ACLRule{
				DistinguishedNameSuffix: "dc=not-example,dc=com",
				Allowed:                 true,
			},
		}
		actualACLs := obj.ACLs

		assert.Equal(t, expectedACLs, actualACLs)
	})
}
