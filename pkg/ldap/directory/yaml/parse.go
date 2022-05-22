package yamldir

import (
	"fmt"
	"slices"
	"strings"

	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
	common "github.com/xunleii/yaldap/pkg/ldap/directory/common"
	"gopkg.in/yaml.v3"
)

// parseLDAPObject parses a YAML mapping node into a LDAP object.
func parseLDAPObject(parent *common.Object, key string, value *yaml.Node) error {
	if strings.Count(key, ":") != 1 {
		return &ParseError{
			err: fmt.Errorf(
				"invalid key: '%s' must be in the form '<type>:<name>' (e.g. 'ou:users')",
				key,
			),
			source: value,
		}
	}

	// extract the DN from the key
	dn := strings.Replace(key, ":", "=", 1)
	if parent := parent.DN(); parent != "" {
		dn = dn + "," + parent
	}

	obj := &common.Object{
		ImplObject: common.ImplObject{
			DN:         dn,
			SubObjects: map[string]*common.Object{},
			Attributes: ldap.Attributes{
				strings.SplitN(key, ":", 2)[0]: []string{strings.SplitN(key, ":", 2)[1]},
			},
		},
	}

	// parse all contents
	seen := map[string]bool{}
	subnodes := slices.Clone(value.Content)
	for i := 0; i < len(subnodes); i += 2 {
		key, value := subnodes[i], subnodes[i+1]

		// skip already seen keys (can happen with merge tags)
		if seen[key.Value] {
			continue
		}

		// resolve aliases nodes
		for value.Kind == yaml.AliasNode {
			value = value.Alias
		}

		// if the sub-node is a 'merge' node, merge the content of the
		// referenced node into the current node (priority merge)
		if key.Kind == yaml.ScalarNode && key.Value == "<<" &&
			(key.Tag == "" || key.Tag == "!" || key.Tag == "!!merge") {
			if value.Kind != yaml.MappingNode {
				return &ParseError{
					err:    fmt.Errorf("only mapping nodes can be merged, got a %s", YamlKindVerbose(value.Kind)),
					source: key,
				}
			}

			subnodes = append(subnodes, value.Content...)
			continue
		}

		switch value.Kind {
		case yaml.MappingNode:
			if err := parseLDAPObject(obj, key.Value, value); err != nil {
				return err
			}
		case yaml.SequenceNode, yaml.ScalarNode:
			if err := parseLDAPAttribute(obj, key.Value, value); err != nil {
				return err
			}
		default:
			// NOTE: this should never happen as the only YAML node type
			//       that can reach this point is a document node
			continue
		}
		seen[key.Value] = true
	}

	parent.SubObjects[key] = obj
	return nil
}

// parseLDAPAttribute parses a YAML sequence or scalar node into a LDAP attribute.
func parseLDAPAttribute(parent *common.Object, key string, value *yaml.Node) error {
	// ignore all null values
	if value.Tag == "!!null" {
		return nil
	}

	if value.Kind != yaml.ScalarNode && value.Kind != yaml.SequenceNode {
		return &ParseError{
			err: fmt.Errorf(
				"invalid attribute type: only a %s or a %s is allowed",
				YamlKindVerbose(yaml.ScalarNode),
				YamlKindVerbose(yaml.SequenceNode),
			),
			source: value,
		}
	}

	if stop, err := handleCustomTags(parent, value); err != nil {
		return err
	} else if stop {
		return nil
	}

	switch value.Kind {
	case yaml.ScalarNode:
		parent.AddAttribute(key, value.Value)
	case yaml.SequenceNode:
		for _, node := range value.Content {
			err := parseLDAPAttribute(parent, key, node)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
