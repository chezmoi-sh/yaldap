package main

import (
	"os"

	"github.com/alecthomas/kong"
	"github.com/xunleii/yaldap/pkg/cmd"
)

func main() {
	var server cmd.Server

	ctx := kong.Parse(
		&server,
		kong.Name("yaldap"),
		kong.Description(`
yaLDAP is an LDAP server that is backed by different read-only data sources,
such as YAML files. It is intended to be lightweight, secure and easy to configure.

    See https://github.com/xunleii/yaldap for more information.
`),
		kong.UsageOnError(),
	)

	if err := ctx.Run(); err != nil {
		server.Logger().Error(err.Error())
		os.Exit(1)
	}
}
