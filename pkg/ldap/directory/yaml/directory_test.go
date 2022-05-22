package yamldir

import (
	"testing"

	"github.com/stretchr/testify/assert"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
	"github.com/xunleii/yaldap/pkg/ldap/directory/common"
)

func TestNewDirectory_ValidYAML(t *testing.T) {
	raw := []byte(`
ou:people:
  uid:alice:
    memberOf: [admin, user, h4ck3r]
    givenname: alice
`)
	expected := &directory{
		entries: &common.Object{
			ImplObject: common.ImplObject{
				SubObjects: map[string]*common.Object{
					"ou:people": {
						ImplObject: common.ImplObject{
							DN:         "ou=people",
							Attributes: ldap.Attributes{"ou": []string{"people"}},
							SubObjects: map[string]*common.Object{
								"uid:alice": {
									ImplObject: common.ImplObject{
										DN: "uid=alice,ou=people",
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
				},
			},
		},
		index: map[string]*common.Object{
			"ou=people": {
				ImplObject: common.ImplObject{
					DN:         "ou=people",
					Attributes: ldap.Attributes{"ou": []string{"people"}},
					SubObjects: map[string]*common.Object{
						"uid:alice": {
							ImplObject: common.ImplObject{
								DN: "uid=alice,ou=people",
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
			"uid=alice,ou=people": {
				ImplObject: common.ImplObject{
					DN: "uid=alice,ou=people",
					Attributes: ldap.Attributes{
						"uid":       []string{"alice"},
						"memberOf":  []string{"admin", "user", "h4ck3r"},
						"givenname": []string{"alice"},
					},
					SubObjects: map[string]*common.Object{},
				},
			},
		},
	}

	directory, err := NewDirectory(raw)

	assert.NoError(t, err)
	assert.Equal(t, expected, directory)
}
