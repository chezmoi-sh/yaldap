package yamldir

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	ldap "github.com/chezmoi-sh/yaldap/pkg/ldap/directory"
	"github.com/chezmoi-sh/yaldap/pkg/ldap/directory/common"
	"gopkg.in/yaml.v3"
)

type (
	// directory represents the current LDAP directory. It contains all entries and an index for quick node search.
	directory struct {
		entries *common.Object
		index   map[string]*common.Object
	}
)

func NewDirectory(url string) (ldap.Directory, error) {
	url = strings.TrimPrefix(url, "file://")
	raw, err := os.ReadFile(url)
	if err != nil {
		return nil, fmt.Errorf("unable to read YAML directory file: %w", err)
	}

	template, err := yamlDirectoryTemplate.Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("unable to parse YAML directory file: %w", err)
	}

	buf := bytes.NewBuffer(nil)
	err = template.Execute(buf, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to parse YAML directory file: %w", err)
	}

	return NewDirectoryFromYAML(buf.Bytes())
}

func NewDirectoryFromYAML(raw []byte) (ldap.Directory, error) {
	directory := &directory{
		entries: &common.Object{
			ImplObject: common.ImplObject{
				Attributes: ldap.Attributes{"objectClass": {"top", "yaLDAPRootDSE"}},
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
				err = parseLDAPObject(directory.entries, key, value)
			case yaml.SequenceNode, yaml.ScalarNode:
				err = parseLDAPAttribute(directory.entries, key, value)
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
	if dn == "" {
		return d.entries
	}

	obj, found := d.index[dn]
	if !found {
		return nil
	}
	return obj
}
