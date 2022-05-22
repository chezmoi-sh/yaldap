package yamldir

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestParseError_Error(t *testing.T) {
	err := &ParseError{
		err:    fmt.Errorf("some error"),
		source: &yaml.Node{Line: 10, Column: 5},
	}
	expected := "invalid LDAP YAML document at line 10, column 5: some error"
	assert.Equal(t, expected, err.Error())
}

func TestParseError_Unwrap(t *testing.T) {
	innerErr := fmt.Errorf("inner error")
	err := &ParseError{
		err:    innerErr,
		source: &yaml.Node{Line: 10, Column: 5},
	}
	assert.Equal(t, innerErr, err.Unwrap())
}
