package yaml

import (
	"fmt"

	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
	"gopkg.in/yaml.v3"
)

type (
	// Directory represents the current LDAP directory. It contains all entries and an index for quick node search.
	Directory struct {
		entries *Object
		index   map[string]*Object
	}
)

func NewDirectory(raw []byte) (*Directory, error) {
	obj := map[string]interface{}{}

	err := yaml.Unmarshal(raw, &obj)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the LDAP directory YAML: %w", err)
	}

	directory := &Directory{index: map[string]*Object{}}
	directory.entries, err = parseObject("", obj, directory.index)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the LDAP directory definition: %w", err)
	}

	return directory, nil
}

func (d Directory) BaseDN(dn string) yaldaplib.Object { return d.index[dn] }
