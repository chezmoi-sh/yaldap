//nolint:goconst
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
	actualResult, err := obj.Bind(password)

	assert.NoError(t, err)
	assert.Equal(t, expectedResult, actualResult)

	// Test with incorrect password
	password = "wrongpassword"
	expectedResult = false
	actualResult, err = obj.Bind(password)

	assert.NoError(t, err)
	assert.Equal(t, expectedResult, actualResult)

	// Test with no bind passwords
	obj.BindPasswords = nil
	password = "password123"
	expectedResult = false
	actualResult, err = obj.Bind(password)

	assert.NoError(t, err)
	assert.Equal(t, expectedResult, actualResult)

	// Test with unsupported PHC algorithm
	obj.BindPasswords = []string{"$unknown$v=0$r=0$salt$hash"}
	password = "password123"
	expectedResult = false
	actualResult, err = obj.Bind(password)

	assert.EqualError(t, err, "unsupported PHC algorithm: unknown")
	assert.Equal(t, expectedResult, actualResult)
}

func TestObjectBindWithHashedPassword(t *testing.T) {
	tests := []struct {
		Name           string
		HashedPassword string
		ExpectedResult bool
	}{
		{
			Name:           "Test with argon2id",
			HashedPassword: "$argon2id$v=19$m=65536,t=10,p=1$fc833b1da8729366224df547834badc7914906b7add02b6e709e1ffe4de56ed3$cbfe0dce36ac1d0db8d869b60cb0f264ea44b2e50d1376cfc4ff3412d73e38c7eebc9d07674b9337297edfe2f64877769b09bbb7f80ef974dc7263eb48002b9f", // yaldap_utils hash argon2 password123
			ExpectedResult: true,
		},
		{
			Name:           "Test with bcrypt",
			HashedPassword: "$bcrypt$v=0$r=8$$243261243038244e4e78745643644d4f7a33442f6a37534e72345a7075586b772f416d58456a2f6e544856706f784b45656446547570332f41474743", // yaldap_utils hash bcrypt password123
			ExpectedResult: true,
		},
		{
			Name:           "Test with pbkdf2",
			HashedPassword: "$pbkdf2sha256$v=0$i=10$67447629899eeb0d6fdb1e4d784a8a78$b467bb3ec3a9c4d46cf0fabb8207f4da139022836168fd29f1258f85f3c4bd6f", // yaldap_utils hash pbkdf2 password123
			ExpectedResult: true,
		},
		{
			Name:           "Test with scrypt",
			HashedPassword: "$scrypt$v=0$ln=16,r=8,p=1$fca08f0f4120c4fd2b2d5e36a114d4fb$fd3db2ea0f59d547d0687ef64c7b2afcdc6f98cbd416442f3ccda41f62a66348", // yaldap_utils hash scrypt password123
			ExpectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			obj := Object{
				ImplObject: ImplObject{
					BindPasswords: []string{tt.HashedPassword},
				},
			}

			actualResult, err := obj.Bind("password123")

			assert.NoError(t, err)
			assert.Equal(t, tt.ExpectedResult, actualResult)
		})
	}
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
