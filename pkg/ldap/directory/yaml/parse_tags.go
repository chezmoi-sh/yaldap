package yamldir

import (
	"fmt"

	"github.com/moznion/go-optional"
	"github.com/xunleii/yaldap/pkg/ldap/directory/common"
	"gopkg.in/yaml.v3"
)

// handleCustomTags handles custom tags that are not supported by the YAML library
// but required to enhence some features for the LDAP directory.
// It returns true if we should stop parsing the node, false otherwise.
func handleCustomTags(parent *common.Object, node *yaml.Node) (bool, error) {
	switch node.Tag {
	case "!!ldap/bind:password":
		if parent.BindPasswords.IsSome() {
			return false, &ParseError{
				err: fmt.Errorf(
					"invalid '%s' tag: only one %s per object is allowed",
					node.Tag,
					node.Tag,
				),
				source: node,
			}
		}

		if node.Kind != yaml.ScalarNode {
			return false, &ParseError{
				err: fmt.Errorf(
					"invalid '%s' type: only a %s is allowed",
					node.Tag,
					YamlKindVerbose(yaml.ScalarNode),
				),
				source: node,
			}
		}
		parent.BindPasswords = optional.Some(node.Value)

	case "!!ldap/acl:allow-on", "!!ldap/acl:deny-on":
		allowed := node.Tag == "!!ldap/acl:allow-on"
		rules := node.Content
		if node.Kind == yaml.ScalarNode {
			rules = []*yaml.Node{node}
		}

		for _, rule := range rules {
			if rule.Kind != yaml.ScalarNode {
				return false, &ParseError{
					err: fmt.Errorf(
						"invalid '%s' type: only a %s is allowed",
						node.Tag,
						YamlKindVerbose(yaml.ScalarNode),
					),
					source: node,
				}
			}

			parent.AddACLRule(common.ACLRule{
				DistinguishedNameSuffix: rule.Value,
				Allowed:                 allowed,
			})
		}
		return true, nil
	}
	return false, nil
}
