package naive

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDirectory(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		error bool
	}{
		{name: "ValidYaml",
			yaml: "uid:alice: {}"},

		{name: "InvalidYaml",
			yaml:  "{[]}",
			error: true},
		{name: "InvalidYamlDefinition",
			yaml:  "uid=alice: {}",
			error: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDirectory([]byte(tt.yaml))

			if !tt.error {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
