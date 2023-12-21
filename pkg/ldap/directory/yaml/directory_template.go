package yamldir

import (
	"os"
	"text/template"

	"github.com/Masterminds/sprig/v3"
)

var yamlDirectoryTemplate = template.
	New("LDAP YAML Directory").
	Funcs(sprig.TxtFuncMap()).
	Funcs(template.FuncMap{
		"readFile": func(p string) (string, error) { s, e := os.ReadFile(p); return string(s), e },
	})
