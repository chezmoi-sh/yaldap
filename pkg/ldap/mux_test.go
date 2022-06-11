package ldap_test

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/jimlambrt/gldap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
	"github.com/xunleii/yaldap/pkg/ldap/yaml"
)

type YamlLdapMuxE2E struct {
	suite.Suite
	server *gldap.Server
}

func (e2e *YamlLdapMuxE2E) SetupTest() {
	e2e.server, _ = gldap.NewServer()
}

func (e2e *YamlLdapMuxE2E) TearDownTest() {
	_ = e2e.server.Stop()
}

func (e2e *YamlLdapMuxE2E) bootstrapLdap(raw string) *ldap.Conn {
	directory, err := yaml.NewDirectory([]byte(raw))
	require.NoError(e2e.T(), err)

	mux := yaldaplib.NewMux(directory)
	err = e2e.server.Router(mux)
	require.NoError(e2e.T(), err)

	go func() { _ = e2e.server.Run(":63636") }()
	conn, err := ldap.DialURL("ldap://localhost:63636")
	require.NoError(e2e.T(), err)

	return conn
}

func (e2e *YamlLdapMuxE2E) TestBind() {
	const yaml = `
cn:alice:
  .#BindPasswordAttr: [password]
  .@password: alice

cn:bob: {}
`
	conn := e2e.bootstrapLdap(yaml)
	defer conn.Close()

	tests := []struct {
		name     string
		dn       string
		password string
		expect   func(assert.TestingT, error, ...interface{}) bool
	}{
		{name: "SuccessfulBind",
			dn:       "cn=alice",
			password: "alice",
			expect:   assert.NoError},
		{name: "InvalidDN",
			dn:       "cn=bob",
			password: "bob",
			expect:   assert.Error},
		{name: "InvalidPassword",
			dn:       "cn=alice",
			password: "bob",
			expect:   assert.Error},
		{name: "NoPassword",
			dn:       "cn=bob",
			password: "bob",
			expect:   assert.Error},
	}

	for _, tt := range tests {
		e2e.T().Run(tt.name, func(t *testing.T) {
			err := conn.Bind(tt.dn, tt.password)
			tt.expect(t, err)
		})
	}
}

func (e2e *YamlLdapMuxE2E) TestSearch() {
	const yaml string = `
dc:org:
  dc:example:
    .@objectclass: [organisation]

    ou:people:
      cn:alice:
        .#BindPasswordAttr: [userpassword]
        .#AllowedDN: ["dc=example,dc=org", "cn=alice,ou=people,dc=example,dc=org"]
        .#DeniedDN: ["dc=org", "ou=people,dc=example,dc=org"]

        .@objectclass: [person]
        .@userpassword: alice

      cn:bob:
        .@objectclass: [person]

  dc:example2:
    .@objectclass: [organisation]
`
	conn := e2e.bootstrapLdap(yaml)
	defer conn.Close()

	tests := []struct {
		name   string
		basedn string
		scope  int
		filter string
		result int
	}{
		{name: "FindAlice",
			basedn: "dc=org",
			scope:  ldap.ScopeWholeSubtree,
			filter: "(cn=alice)",
			result: 1}, // cn=alice,ou=people,dc=example,dc=org
		{name: "FindAllObjectclass",
			basedn: "dc=org",
			scope:  ldap.ScopeWholeSubtree,
			filter: "(objectclass=*)",
			result: 2}, // cn=alice,ou=people,dc=example,dc=org & dc=example,dc=org (cn=bob,ou=people,dc=example,dc=org & dc=example2,dc=org rejected by ACL)
		{name: "FindAllOuOrCn",
			basedn: "dc=org",
			scope:  ldap.ScopeWholeSubtree,
			filter: "(|(ou=*)(cn=*))",
			result: 1}, // cn=alice,ou=people,dc=example,dc=org (cn=bob,ou=people,dc=example,dc=org & ou=people,dc=example,dc=org rejected by ACL)

		{name: "InvalidDN",
			basedn: "dc=alice",
			scope:  ldap.ScopeWholeSubtree,
			filter: "(objectclass=*)",
			result: 0},
		{name: "InvalidScope",
			basedn: "dc=org",
			scope:  ldap.ScopeSingleLevel,
			filter: "(cn=alice)",
			result: 0},
	}

	err := conn.Bind("cn=alice,ou=people,dc=example,dc=org", "alice")
	e2e.NoError(err)

	for _, tt := range tests {
		e2e.T().Run(tt.name, func(t *testing.T) {
			req := ldap.NewSearchRequest(tt.basedn, tt.scope, 0, 0, 0, false, tt.filter, nil, nil)
			res, err := conn.Search(req)
			require.NoError(t, err)

			assert.Len(t, res.Entries, tt.result)
		})
	}
}

func (e2e *YamlLdapMuxE2E) TestAdd() {
	conn := e2e.bootstrapLdap(`
cn:alice:
 .#BindPasswordAttr: [password]
 .@userpassword: alice
`)
	defer conn.Close()

	err := conn.Bind("cn=alice", "alice")
	require.NoError(e2e.T(), err)

	err = conn.Add(ldap.NewAddRequest("cn=bob", nil))
	e2e.Error(err)
}

func (e2e *YamlLdapMuxE2E) TestModify() {
	conn := e2e.bootstrapLdap(`
cn:alice:
 .#BindPasswordAttr: [password]
 .@userpassword: alice
`)
	defer conn.Close()

	err := conn.Bind("cn=alice", "alice")
	require.NoError(e2e.T(), err)

	err = conn.Modify(ldap.NewModifyRequest("cn=alice", nil))
	e2e.Error(err)
}

func (e2e *YamlLdapMuxE2E) TestDelete() {
	conn := e2e.bootstrapLdap(`
cn:alice:
 .#BindPasswordAttr: [password]
 .@userpassword: alice
`)
	defer conn.Close()

	err := conn.Bind("cn=alice", "alice")
	require.NoError(e2e.T(), err)

	err = conn.Del(ldap.NewDelRequest("cn=alice", nil))
	e2e.Error(err)
}

func TestLdapMuxE2E(t *testing.T) { suite.Run(t, new(YamlLdapMuxE2E)) }
