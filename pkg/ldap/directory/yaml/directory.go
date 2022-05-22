package yamldir

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
	"github.com/xunleii/yaldap/pkg/ldap/directory/common"
	"gopkg.in/yaml.v3"
)

type (
	// directory represents the current LDAP directory. It contains all entries and an index for quick node search.
	directory struct {
		entries *common.Object
		index   map[string]*common.Object
	}
)

func NewDirectory(raw []byte) (ldap.Directory, error) {
	directory := &directory{
		entries: &common.Object{
			ImplObject: common.ImplObject{
				SubObjects: map[string]*common.Object{},
			},
		},
		index: map[string]*common.Object{},
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))

	for {
		var document yaml.Node

		err := dec.Decode(&document)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("invalid LDAP YAML document: %w", err)
		}

		switch {
		case yaml.DocumentNode != document.Kind || len(document.Content) < 1:
			continue
		case yaml.MappingNode != document.Content[0].Kind:
			return nil, &ParseError{
				err: fmt.Errorf(
					"expected a %s as root node, got a %s",
					YamlKindVerbose(yaml.MappingNode),
					YamlKindVerbose(document.Content[0].Kind),
				),
				source: &document,
			}
		}

		node := document.Content[0]
		for idx := 0; idx < len(node.Content); idx += 2 {
			key, value := node.Content[idx], node.Content[idx+1]

			switch value.Kind {
			case yaml.MappingNode:
				err = parseLDAPObject(directory.entries, key.Value, value)
			case yaml.SequenceNode, yaml.ScalarNode:
				err = parseLDAPAttribute(directory.entries, key.Value, value)
			}

			if err != nil {
				return nil, err
			}
		}
	}

	indexDirectory(directory.entries, directory.index)
	return directory, nil
}

func indexDirectory(obj *common.Object, index map[string]*common.Object) {
	index[obj.DN()] = obj

	for _, obj := range obj.SubObjects {
		indexDirectory(obj, index)
	}

	// delete the root object from the index
	delete(index, "")
}

func (d directory) BaseDN(dn string) ldap.Object {
	obj, found := d.index[dn]
	if !found {
		return nil
	}
	return obj
}
