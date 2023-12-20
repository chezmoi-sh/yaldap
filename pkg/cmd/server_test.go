package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/madflojo/testcerts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_YAML_Simple(t *testing.T) {
	server := Server{AddrListen: fmt.Sprintf("localhost:%d", freePort(t))}
	server.Base.Log.Format = "test"
	server.Backend.Name = "yaml"
	server.Backend.URL = "file://../ldap/directory/yaml/fixtures/basic.yaml" //nolint:goconst

	go func() { assert.NoError(t, server.Run(nil)) }()

	var client *ldap.Conn
	require.Eventually(t,
		func() bool {
			var err error
			client, err = ldap.DialURL(fmt.Sprintf("ldap://%s", server.AddrListen))
			return assert.NoError(t, err)
		},
		500*time.Millisecond,
		100*time.Millisecond,
	)
	defer client.Close()

	err := client.Bind("cn=alice,ou=people,c=global,dc=example,dc=org", "alice")
	require.NoError(t, err)
}

func TestServer_YAML_WithTLS(t *testing.T) {
	ca := testcerts.NewCA()
	cert, err := ca.NewKeyPair("localhost")
	require.NoError(t, err)

	server := Server{AddrListen: fmt.Sprintf("localhost:%d", freePort(t))}
	server.Base.Log.Format = "test"
	server.Backend.Name = "yaml"
	server.Backend.URL = "file://../ldap/directory/yaml/fixtures/basic.yaml"
	server.TLS.Enable = true
	server.TLS.CAFile = string(ca.PublicKey())
	server.TLS.CertFile = string(cert.PublicKey())
	server.TLS.KeyFile = string(cert.PrivateKey())

	go func() { assert.NoError(t, server.Run(nil)) }()

	var client *ldap.Conn
	require.Eventually(t,
		func() bool {
			client, err = ldap.DialURL(
				fmt.Sprintf("ldaps://%s", server.AddrListen),
				ldap.DialWithTLSConfig(&tls.Config{RootCAs: ca.CertPool()}),
			)
			return assert.NoError(t, err)
		},
		500*time.Millisecond,
		100*time.Millisecond,
	)
	defer client.Close()

	err = client.Bind("cn=alice,ou=people,c=global,dc=example,dc=org", "alice")
	require.NoError(t, err)
}

func TestServer_YAML_WithMutualTLS(t *testing.T) {
	ca := testcerts.NewCA()
	keypair, err := ca.NewKeyPair("localhost")
	require.NoError(t, err)

	server := Server{AddrListen: fmt.Sprintf("localhost:%d", freePort(t))}
	server.Base.Log.Format = "test"
	server.Backend.Name = "yaml"
	server.Backend.URL = "file://../ldap/directory/yaml/fixtures/basic.yaml"
	server.TLS.Enable = true
	server.TLS.MutualTLS = true
	server.TLS.CAFile = string(ca.PublicKey())
	server.TLS.CertFile = string(keypair.PublicKey())
	server.TLS.KeyFile = string(keypair.PrivateKey())

	go func() { assert.NoError(t, server.Run(nil)) }()

	var client *ldap.Conn

	keypair, err = ca.NewKeyPair("localhost")
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(keypair.PublicKey(), keypair.PrivateKey())
	require.NoError(t, err)

	require.Eventually(t,
		func() bool {
			client, err = ldap.DialURL(
				fmt.Sprintf("ldaps://%s", server.AddrListen),
				ldap.DialWithTLSConfig(&tls.Config{
					RootCAs:      ca.CertPool(),
					Certificates: []tls.Certificate{cert},
				}),
			)
			return assert.NoError(t, err)
		},
		500*time.Millisecond,
		100*time.Millisecond,
	)
	defer client.Close()

	err = client.Bind("cn=alice,ou=people,c=global,dc=example,dc=org", "alice")
	require.NoError(t, err)
}

// freePort returns a free port number.
func freePort(t *testing.T) int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(t, err)

	l, err := net.ListenTCP("tcp", addr)
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}