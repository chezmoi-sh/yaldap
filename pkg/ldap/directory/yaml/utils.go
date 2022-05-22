package yamldir

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ParseError describes a failure occurring during the parsing of the YAML definition.
type ParseError struct {
	err    error
	source *yaml.Node
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("invalid LDAP YAML document at line %d, column %d: %s", e.source.Line, e.source.Column, e.err.Error())
}
func (e *ParseError) Unwrap() error { return e.err }

var yamlKindName = map[yaml.Kind]string{
	yaml.DocumentNode: "document",
	yaml.SequenceNode: "sequence node (aka. list/array)",
	yaml.MappingNode:  "mapping node (aka. dictionary)",
	yaml.ScalarNode:   "scalar node (aka. primitive)",
	yaml.AliasNode:    "alias node (aka. reference)",
}

type YamlKindVerbose yaml.Kind

func (k YamlKindVerbose) String() string {
	return yamlKindName[yaml.Kind(k)]
}
