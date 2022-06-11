package yaml

import (
	"fmt"

	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
	"gopkg.in/yaml.v3"
)

type (
	// directory represents the current LDAP directory. It contains all entries and an index for quick node search.
	directory struct {
		entries *object
		index   map[string]*object
	}
)

func NewDirectory(raw []byte) (*directory, error) {
	obj := map[string]interface{}{}

	err := yaml.Unmarshal(raw, &obj)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the LDAP directory YAML: %w", err)
	}

	directory := &directory{index: map[string]*object{}}
	directory.entries, err = parseObject("", obj, directory.index)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the LDAP directory definition: %w", err)
	}

	return directory, nil
}

func (d directory) BaseDN(dn string) yaldaplib.Object { return d.index[dn] }
