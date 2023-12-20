package yamldir

import (
	"testing"

	"github.com/stretchr/testify/assert"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
	"github.com/xunleii/yaldap/pkg/ldap/directory/common"
)

func TestNewDirectory_NoFile(t *testing.T) {
	directory, err := NewDirectory("fixtures/does-not-exist.yaml")

	assert.EqualError(t, err, "unable to read LDAP YAML file: open fixtures/does-not-exist.yaml: no such file or directory")
	assert.Nil(t, directory)
}

func TestNewDirectoryFromYAML_ValidYAML(t *testing.T) {
	raw := []byte(`
ou:people:
  uid:alice:
    memberOf: [admin, user, h4ck3r]
    givenname: alice
`)
	expected := &directory{
		entries: &common.Object{
			ImplObject: common.ImplObject{
				Attributes: ldap.Attributes{"objectClass": {"top", "yaLDAPRootDSE"}},
				SubObjects: map[string]*common.Object{
					"ou:people": {
						ImplObject: common.ImplObject{
							DN:         "ou=people",
							Attributes: ldap.Attributes{"ou": {"people"}},
							SubObjects: map[string]*common.Object{
								"uid:alice": {
									ImplObject: common.ImplObject{
										DN: "uid=alice,ou=people",
										Attributes: ldap.Attributes{
											"uid":       {"alice"},
											"memberOf":  {"admin", "user", "h4ck3r"},
											"givenname": {"alice"},
										},
										SubObjects: map[string]*common.Object{},
									},
								},
							},
						},
					},
				},
			},
		},
		index: map[string]*common.Object{
			"ou=people": {
				ImplObject: common.ImplObject{
					DN:         "ou=people",
					Attributes: ldap.Attributes{"ou": {"people"}},
					SubObjects: map[string]*common.Object{
						"uid:alice": {
							ImplObject: common.ImplObject{
								DN: "uid=alice,ou=people",
								Attributes: ldap.Attributes{
									"uid":       {"alice"},
									"memberOf":  {"admin", "user", "h4ck3r"},
									"givenname": {"alice"},
								},
								SubObjects: map[string]*common.Object{},
							},
						},
					},
				},
			},
			"uid=alice,ou=people": {
				ImplObject: common.ImplObject{
					DN: "uid=alice,ou=people",
					Attributes: ldap.Attributes{
						"uid":       {"alice"},
						"memberOf":  {"admin", "user", "h4ck3r"},
						"givenname": {"alice"},
					},
					SubObjects: map[string]*common.Object{},
				},
			},
		},
	}

	directory, err := NewDirectoryFromYAML(raw)

	assert.NoError(t, err)
	assert.Equal(t, expected, directory)
}

func TestDirectory_BaseDN(t *testing.T) {
	raw := []byte(`
ou:people:
  uid:alice: {}
`)
	directory, err := NewDirectoryFromYAML(raw)
	assert.NoError(t, err)

	t.Run("ou=people", func(t *testing.T) {
		actual := directory.BaseDN("ou=people")
		expected := &common.Object{
			ImplObject: common.ImplObject{
				DN:         "ou=people",
				Attributes: ldap.Attributes{"ou": {"people"}},
				SubObjects: map[string]*common.Object{
					"uid:alice": {
						ImplObject: common.ImplObject{
							DN:         "uid=alice,ou=people",
							Attributes: ldap.Attributes{"uid": {"alice"}},
							SubObjects: map[string]*common.Object{},
						},
					},
				},
			},
		}

		assert.Equal(t, expected, actual)
	})

	t.Run("uid=alice,ou=people", func(t *testing.T) {
		actual := directory.BaseDN("uid=alice,ou=people")
		expected := &common.Object{
			ImplObject: common.ImplObject{
				DN:         "uid=alice,ou=people",
				Attributes: ldap.Attributes{"uid": {"alice"}},
				SubObjects: map[string]*common.Object{},
			},
		}

		assert.Equal(t, expected, actual)
	})

	t.Run("empty DN", func(t *testing.T) {
		actual := directory.BaseDN("")
		expected := &common.Object{
			ImplObject: common.ImplObject{
				DN:         "",
				Attributes: ldap.Attributes{"objectClass": {"top", "yaLDAPRootDSE"}},
				SubObjects: map[string]*common.Object{
					"ou:people": {
						ImplObject: common.ImplObject{
							DN:         "ou=people",
							Attributes: ldap.Attributes{"ou": {"people"}},
							SubObjects: map[string]*common.Object{
								"uid:alice": {
									ImplObject: common.ImplObject{
										DN:         "uid=alice,ou=people",
										Attributes: ldap.Attributes{"uid": {"alice"}},
										SubObjects: map[string]*common.Object{},
									},
								},
							},
						},
					},
				},
			},
		}

		assert.Equal(t, expected, actual)
	})

	t.Run("DN not found", func(t *testing.T) {
		actual := directory.BaseDN("cn=does-not-exist")

		assert.Nil(t, actual)
	})
}
