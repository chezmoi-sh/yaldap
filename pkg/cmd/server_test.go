package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/go-ldap/ldap/v3"
	"github.com/madflojo/testcerts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_Defaults(t *testing.T) {
	var actual, expected Server
	actual.Base = &Base{}
	expected.Base = &Base{}

	expected.ListenAddr = ":389"
	expected.Backend.Name = "yaml"
	expected.Backend.URL = "file://../ldap/directory/yaml/fixtures/basic.yaml" //nolint:goconst
	expected.SessionTTL = 168 * time.Hour
	expected.TLS.Enable = false
	expected.TLS.MutualTLS = false

	os.Args = []string{"...", "--backend.name", "yaml", "--backend.url", "file://../ldap/directory/yaml/fixtures/basic.yaml"}
	kong.Parse(&actual)
	assert.Equal(t, expected, actual)
}

func TestServer_YAML_Simple(t *testing.T) {
	server := Server{ListenAddr: fmt.Sprintf("localhost:%d", freePort(t))}
	server.Base = &Base{}
	server.Base.Log.Format = "test"
	server.Backend.Name = "yaml"
	server.Backend.URL = "file://../ldap/directory/yaml/fixtures/basic.yaml"
	server.SessionTTL = time.Hour

	go func() { assert.NoError(t, server.Run(nil)) }()

	var client *ldap.Conn
	require.Eventually(t,
		func() bool {
			var err error
			client, err = ldap.DialURL(fmt.Sprintf("ldap://%s", server.ListenAddr))
			return assert.NoError(t, err)
		},
		500*time.Millisecond,
		100*time.Millisecond,
	)
	defer client.Close()

	err := client.Bind("cn=alice,ou=people,c=fr,dc=example,dc=org", "alice")
	require.NoError(t, err)
}

func TestServer_YAML_WithTLS(t *testing.T) {
	ca := testcerts.NewCA()
	cert, err := ca.NewKeyPair("localhost")
	require.NoError(t, err)

	server := Server{ListenAddr: fmt.Sprintf("localhost:%d", freePort(t))}
	server.Base = &Base{}
	server.Base.Log.Format = "test"
	server.Backend.Name = "yaml"
	server.Backend.URL = "file://../ldap/directory/yaml/fixtures/basic.yaml"
	server.SessionTTL = time.Hour
	server.TLS.Enable = true
	server.TLS.CAFile = ca.PublicKey()
	server.TLS.CertFile = cert.PublicKey()
	server.TLS.KeyFile = cert.PrivateKey()

	go func() { assert.NoError(t, server.Run(nil)) }()

	var client *ldap.Conn
	require.Eventually(t,
		func() bool {
			client, err = ldap.DialURL(
				fmt.Sprintf("ldaps://%s", server.ListenAddr),
				ldap.DialWithTLSConfig(&tls.Config{RootCAs: ca.CertPool()}),
			)
			return assert.NoError(t, err)
		},
		500*time.Millisecond,
		100*time.Millisecond,
	)
	defer client.Close()

	err = client.Bind("cn=alice,ou=people,c=fr,dc=example,dc=org", "alice")
	require.NoError(t, err)
}

func TestServer_YAML_WithMutualTLS(t *testing.T) {
	ca := testcerts.NewCA()
	keypair, err := ca.NewKeyPair("localhost")
	require.NoError(t, err)

	server := Server{ListenAddr: fmt.Sprintf("localhost:%d", freePort(t))}
	server.Base = &Base{}
	server.Base.Log.Format = "test"
	server.Backend.Name = "yaml"
	server.Backend.URL = "file://../ldap/directory/yaml/fixtures/basic.yaml"
	server.SessionTTL = time.Hour
	server.TLS.Enable = true
	server.TLS.MutualTLS = true
	server.TLS.CAFile = ca.PublicKey()
	server.TLS.CertFile = keypair.PublicKey()
	server.TLS.KeyFile = keypair.PrivateKey()

	go func() { assert.NoError(t, server.Run(nil)) }()

	var client *ldap.Conn

	keypair, err = ca.NewKeyPair("localhost")
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(keypair.PublicKey(), keypair.PrivateKey())
	require.NoError(t, err)

	require.Eventually(t,
		func() bool {
			client, err = ldap.DialURL(
				fmt.Sprintf("ldaps://%s", server.ListenAddr),
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

	err = client.Bind("cn=alice,ou=people,c=fr,dc=example,dc=org", "alice")
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
