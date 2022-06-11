package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	"github.com/xunleii/yaldap/pkg/ldap"
	"github.com/xunleii/yaldap/pkg/ldap/yaml"
)

func main() {
	// turn on debug logging
	l := hclog.New(&hclog.LoggerOptions{
		Name:  "simple-bind-logger",
		Level: hclog.Debug,
	})

	// create a new server
	s, err := gldap.NewServer(gldap.WithLogger(l), gldap.WithDisablePanicRecovery())
	if err != nil {
		log.Fatalf("unable to create server: %s", err.Error())
	}

	dir, _ := yaml.NewDirectory([]byte(directoryYaml))
	srv := ldap.NewMux(dir)

	// create a router and add a bind handler
	s.Router(srv.Mux)
	go s.Run(":10389") // listen on port 10389

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	select {
	case <-ctx.Done():
		log.Printf("\nstopping directory")
		s.Stop()
	}
}

const directoryYaml = `
dc:org:
  cn:example:
    ou:people:
      .@objectclass: organizationalUnit

      uid:alice:
        .@objectclass: [top, person, organizationalPerson, inetOrgPerson]
        .@cn: alice eve smith
        .@givenname: alice 
        .@sn: smith
        .@ou: people
        .@description: friend of Rivest, Shamir and Adleman
        .@password: '{SSHA}U3waGJVC7MgXYc0YQe7xv7sSePuTP8zN'
        .@email: alice@example.org
`
