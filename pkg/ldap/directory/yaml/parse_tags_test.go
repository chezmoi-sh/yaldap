package yamldir

import (
	"testing"

	"github.com/chezmoi-sh/yaldap/pkg/ldap/directory/common"
	"github.com/moznion/go-optional"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestHandleCustomTags_BindPassword(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		yaml := &yaml.Node{Tag: "!!ldap/bind:password", Kind: yaml.ScalarNode, Value: "alice"}
		actual := &common.Object{}
		expected := &common.Object{ImplObject: common.ImplObject{BindPasswords: optional.Some("alice")}}

		stop, err := handleCustomTags(actual, yaml)

		assert.NoError(t, err)
		assert.False(t, stop)
		assert.Equal(t, expected, actual)
	})

	t.Run("Invalid/AlreadySet", func(t *testing.T) {
		yaml := &yaml.Node{Tag: "!!ldap/bind:password", Kind: yaml.ScalarNode, Value: "alice"}
		actual := &common.Object{ImplObject: common.ImplObject{BindPasswords: optional.Some("bob")}}
		expectedErr := "invalid LDAP YAML document at line 0, column 0: invalid '!!ldap/bind:password' tag: only one !!ldap/bind:password per object is allowed"

		_, err := handleCustomTags(actual, yaml)
		assert.EqualError(t, err, expectedErr)
	})

	t.Run("Invalid/MultiplePasswords", func(t *testing.T) {
		yaml := &yaml.Node{Tag: "!!ldap/bind:password", Kind: yaml.SequenceNode}
		actual := &common.Object{}
		expectedErr := "invalid LDAP YAML document at line 0, column 0: invalid '!!ldap/bind:password' type: only a scalar node (aka. primitive) is allowed"

		_, err := handleCustomTags(actual, yaml)
		assert.EqualError(t, err, expectedErr)
	})
}

func TestHandleCustomTags_ACLAllowOn(t *testing.T) {
	t.Run("Valid/SingleRule", func(t *testing.T) {
		yaml := &yaml.Node{Tag: "!!ldap/acl:allow-on", Kind: yaml.ScalarNode, Value: "ou=subgroup,dc=example,dc=org"}
		actual := &common.Object{}
		expected := &common.Object{ImplObject: common.ImplObject{
			ACLs: common.ACLRuleSet{{DistinguishedNameSuffix: "ou=subgroup,dc=example,dc=org", Allowed: true}},
		}}

		stop, err := handleCustomTags(actual, yaml)

		assert.NoError(t, err)
		assert.True(t, stop)
		assert.Equal(t, expected, actual)
	})

	t.Run("Valid/MultipleRules", func(t *testing.T) {
		yaml := &yaml.Node{
			Tag:  "!!ldap/acl:allow-on",
			Kind: yaml.SequenceNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "ou=subgroup,dc=example,dc=org"},
				{Kind: yaml.ScalarNode, Value: "ou=othergroup,dc=example,dc=org"},
			},
		}
		actual := &common.Object{}
		expected := &common.Object{ImplObject: common.ImplObject{
			ACLs: common.ACLRuleSet{
				{DistinguishedNameSuffix: "ou=othergroup,dc=example,dc=org", Allowed: true},
				{DistinguishedNameSuffix: "ou=subgroup,dc=example,dc=org", Allowed: true},
			},
		}}

		stop, err := handleCustomTags(actual, yaml)

		assert.NoError(t, err)
		assert.True(t, stop)
		assert.Equal(t, expected, actual)
	})

	t.Run("Invalid/MultipleTypeRules", func(t *testing.T) {
		yaml := &yaml.Node{
			Tag:  "!!ldap/acl:allow-on",
			Kind: yaml.SequenceNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "ou=subgroup,dc=example,dc=org"},
				{Kind: yaml.MappingNode},
			},
		}
		actual := &common.Object{}
		expectedErr := "invalid LDAP YAML document at line 0, column 0: invalid '!!ldap/acl:allow-on' type: only a scalar node (aka. primitive) is allowed"

		_, err := handleCustomTags(actual, yaml)
		assert.EqualError(t, err, expectedErr)
	})
}

func TestHandleCustomTags_ACLDenyOn(t *testing.T) {
	t.Run("Valid/SingleRule", func(t *testing.T) {
		yaml := &yaml.Node{Tag: "!!ldap/acl:deny-on", Kind: yaml.ScalarNode, Value: "ou=subgroup,dc=example,dc=org"}
		actual := &common.Object{}
		expected := &common.Object{ImplObject: common.ImplObject{
			ACLs: common.ACLRuleSet{{DistinguishedNameSuffix: "ou=subgroup,dc=example,dc=org", Allowed: false}},
		}}

		stop, err := handleCustomTags(actual, yaml)

		assert.NoError(t, err)
		assert.True(t, stop)
		assert.Equal(t, expected, actual)
	})

	t.Run("Valid/MultipleRules", func(t *testing.T) {
		yaml := &yaml.Node{
			Tag:  "!!ldap/acl:deny-on",
			Kind: yaml.SequenceNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "ou=subgroup,dc=example,dc=org"},
				{Kind: yaml.ScalarNode, Value: "ou=othergroup,dc=example,dc=org"},
			},
		}
		actual := &common.Object{}
		expected := &common.Object{ImplObject: common.ImplObject{
			ACLs: common.ACLRuleSet{
				{DistinguishedNameSuffix: "ou=othergroup,dc=example,dc=org", Allowed: false},
				{DistinguishedNameSuffix: "ou=subgroup,dc=example,dc=org", Allowed: false},
			},
		}}

		stop, err := handleCustomTags(actual, yaml)

		assert.NoError(t, err)
		assert.True(t, stop)
		assert.Equal(t, expected, actual)
	})

	t.Run("Invalid/MultipleTypeRules", func(t *testing.T) {
		yaml := &yaml.Node{
			Tag:  "!!ldap/acl:deny-on",
			Kind: yaml.SequenceNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "ou=subgroup,dc=example,dc=org"},
				{Kind: yaml.MappingNode},
			},
		}
		actual := &common.Object{}
		expectedErr := "invalid LDAP YAML document at line 0, column 0: invalid '!!ldap/acl:deny-on' type: only a scalar node (aka. primitive) is allowed"

		_, err := handleCustomTags(actual, yaml)
		assert.EqualError(t, err, expectedErr)
	})
}
