package main

import (
	"os"

	"github.com/alecthomas/kong"
	"github.com/chezmoi-sh/yaldap/pkg/cmd"
)

// yaLDAP represents the main application struct, interpretted by kong.
type yaLDAP struct {
	cmd.Base `embed:""`

	Server cmd.Server `cmd:"" name:"run" help:"Start the yaLDAP server"`
	Tools  cmd.Tools  `cmd:"" name:"tools" help:"yaLDAP utilities"`
}

func main() {
	var yaldap yaLDAP

	yaldap.Server.Base = &yaldap.Base
	yaldap.Tools.Base = &yaldap.Base

	// Parse command-line arguments using kong.
	ctx := kong.Parse(
		&yaldap,
		kong.Name("yaldap"),
		kong.Description(`
yaLDAP is an LDAP server that is backed by different read-only data sources,
such as YAML files. It is intended to be lightweight, secure and easy to configure.

    See https://github.com/chezmoi-sh/yaldap for more information.
`),
		kong.UsageOnError(),
	)

	if err := ctx.Run(); err != nil {
		yaldap.Logger().Error(err.Error())
		os.Exit(1)
	}
}
