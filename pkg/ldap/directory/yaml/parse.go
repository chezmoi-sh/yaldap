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
func parseLDAPObject(parent *common.Object, key, value *yaml.Node) error {
	if strings.Count(key.Value, ":") != 1 {
		return &ParseError{
			err: fmt.Errorf(
				"invalid key: '%s' must be in the form '<type>:<name>' (e.g. 'ou:users')",
				key.Value,
			),
			source: value,
		}
	}

	// extract the DN from the key
	dn := strings.Replace(key.Value, ":", "=", 1)
	if parent := parent.DN(); parent != "" {
		dn = dn + "," + parent
	}

	obj := &common.Object{
		ImplObject: common.ImplObject{
			DN:         dn,
			SubObjects: map[string]*common.Object{},
			Attributes: ldap.Attributes{
				strings.SplitN(key.Value, ":", 2)[0]: []string{strings.SplitN(key.Value, ":", 2)[1]},
			},
		},
	}

	// parse all contents
	seen := map[string]bool{}
	subnodes := slices.Clone(value.Content)
	for i := 0; i < len(subnodes); i += 2 {
		skey, svalue := subnodes[i], subnodes[i+1]

		// skip already seen keys (can happen with merge tags)
		if seen[skey.Value] {
			continue
		}

		// resolve aliases nodes
		for svalue.Kind == yaml.AliasNode {
			svalue = svalue.Alias
		}

		// if the sub-node is a 'merge' node, merge the content of the
		// referenced node into the current node (priority merge)
		if skey.Kind == yaml.ScalarNode && skey.Value == "<<" &&
			(skey.Tag == "" || skey.Tag == "!" || skey.Tag == "!!merge") {
			if svalue.Kind != yaml.MappingNode {
				return &ParseError{
					err:    fmt.Errorf("only mapping nodes can be merged, got a %s", YamlKindVerbose(svalue.Kind)),
					source: skey,
				}
			}

			subnodes = append(subnodes, svalue.Content...)
			continue
		}

		switch svalue.Kind {
		case yaml.MappingNode:
			if err := parseLDAPObject(obj, skey, svalue); err != nil {
				return err
			}
		case yaml.SequenceNode, yaml.ScalarNode:
			if err := parseLDAPAttribute(obj, skey, svalue); err != nil {
				return err
			}
		default:
			// NOTE: this should never happen as the only YAML node type
			//       that can reach this point is a document node
			continue
		}
		seen[skey.Value] = true
	}

	parent.SubObjects[key.Value] = obj
	return nil
}

// parseLDAPAttribute parses a YAML sequence or scalar node into a LDAP attribute.
func parseLDAPAttribute(parent *common.Object, key, value *yaml.Node) error {
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

	for name := range parent.Attributes() {
		if strings.EqualFold(name, key.Value) && name != key.Value {
			return &ParseError{
				err: fmt.Errorf(
					"invalid attribute: '%s' is already defined (case-insensitive match with '%s')",
					key.Value,
					name,
				),
				source: key,
			}
		}
	}

	switch value.Kind {
	case yaml.ScalarNode:
		parent.AddAttribute(key.Value, value.Value)
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
