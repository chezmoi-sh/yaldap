package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/jimlambrt/gldap"
	"github.com/xunleii/yaldap/internal/ldap/auth"
	"github.com/xunleii/yaldap/pkg/ldap"
	"github.com/xunleii/yaldap/pkg/ldap/directory"
	yamldir "github.com/xunleii/yaldap/pkg/ldap/directory/yaml"
	"github.com/xunleii/yaldap/pkg/utils"
	"golang.org/x/sync/errgroup"
)

type Server struct {
	Base `embed:""`

	ListenAddr string `name:"listen-address" help:"Address to listen on" default:":389"`

	Backend struct {
		Name string `name:"name" help:"Backend which stores the data" enum:"yaml" required:"" placeholder:"BACKEND"`
		URL  string `name:"url" help:"URL used to connect to the backend" required:"" placeholder:"URL"`
	} `embed:"" prefix:"backend."`

	TLS struct {
		Enable    bool   `name:"tls" help:"Enable TLS" default:"false" negatable:""`
		MutualTLS bool   `name:"mtls" help:"Enable mutual TLS" default:"false" negatable:""`
		CAFile    []byte `name:"tls.ca" help:"Path to the CA file" optional:"" type:"filecontent" placeholder:"PATH"`
		CertFile  []byte `name:"tls.cert" help:"Path to the certificate file" optional:"" type:"filecontent" placeholder:"PATH"`
		KeyFile   []byte `name:"tls.key" help:"Path to the key file" optional:"" type:"filecontent" placeholder:"PATH"`
	} `embed:""`

	SessionTTL time.Duration `name:"session-ttl" help:"Duration of a BIND session before it expires" default:"168h"`
}

// Run starts the yaLDAP server using the configuration passed to the command.
func (s Server) Run(_ *kong.Context) error {
	logger := s.Logger()

	directory, err := s.NewDirectory()
	if err != nil {
		return err
	}

	tlsConfig, err := s.TLSConfig()
	if err != nil {
		return err
	}

	server, err := gldap.NewServer(
		gldap.WithLogger(&utils.HashicorpLoggerWrapper{Logger: logger}),
	)
	if err != nil {
		return err
	}

	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)

	err = server.Router(ldap.NewMux(logger, directory, auth.NewSessions(ctx, s.SessionTTL)))
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return server.Run(s.ListenAddr, gldap.WithTLSConfig(tlsConfig))
	})

	// Graceful shutdown.
	<-ctx.Done()
	if err := server.Stop(); err != nil {
		return err
	}
	return g.Wait()
}

func (s Server) NewDirectory() (directory.Directory, error) {
	// Get the directory builder based on the backend name.
	switch s.Backend.Name {
	case "yaml": //nolint:goconst
		return yamldir.NewDirectory(s.Backend.URL)
	default:
		return nil, fmt.Errorf("unknown backend: %s, only `yaml` is supported", s.Backend.Name)
	}
}

func (s Server) TLSConfig() (*tls.Config, error) {
	if !s.TLS.Enable && !s.TLS.MutualTLS {
		return nil, nil
	}

	cert, err := tls.X509KeyPair(s.TLS.CertFile, s.TLS.KeyFile)
	if err != nil {
		return nil, err
	}

	if !s.TLS.MutualTLS {
		// No mutual TLS, just return the certificate.
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}, nil
	}

	// CA certificates are encoded in PEM format, so we need to decode it
	// first in order to use it.
	caCertPool := x509.NewCertPool()
	caPEMBlock := s.TLS.CAFile
	for {
		var caDERBlock *pem.Block

		caDERBlock, caPEMBlock = pem.Decode(caPEMBlock)
		if caDERBlock == nil {
			break
		}
		if caDERBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(caDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			caCertPool.AddCert(cert)
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}
