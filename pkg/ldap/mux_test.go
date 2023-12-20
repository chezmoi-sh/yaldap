package ldap_test

import (
	"io"
	"log/slog"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/jimlambrt/gldap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/xunleii/yaldap/pkg/ldap"
	yamldir "github.com/xunleii/yaldap/pkg/ldap/directory/yaml"
)

type (
	LDAPTestSuite struct {
		suite.Suite
		*gldap.Server
	}

	ResponseEntryHelper      struct{ *goldap.Entry }
	ResponseEntriesHelper    []*goldap.Entry
	ResponseEntryExpectation struct {
		DN         string
		Attributes map[string][]string
	}
	ResponseEntriesExpectation []ResponseEntryExpectation
)

func (suite *LDAPTestSuite) SetupSuite() {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	directory, err := yamldir.NewDirectoryFromYAML([]byte(`
dc:org:
  objectClass: organization
  
  dc:example:
    objectClass: organization
  
    ou:people:
      cn:alice:
        .acl:
          - !!ldap/acl:allow-on dc=example,dc=org
          - !!ldap/acl:deny-on cn=bob,ou=people,dc=example,dc=org
  
        objectClass: person
        userpassword: !!ldap/bind:password alice
  
      cn:bob:
        objectClass: person
        userpassword: !!ldap/bind:password ""

      cn:charlie:
        objectClass: person
  
  dc:example2:
    objectClass: organization
`))
	suite.Require().NoError(err)

	suite.Server, err = gldap.NewServer()
	suite.Require().NoError(err)

	err = suite.Server.Router(ldap.NewMux(logger, directory))
	suite.Require().NoError(err)

	go func() {
		err := suite.Server.Run(":10389")
		suite.NoError(err)
	}()

	suite.Require().Eventually(
		func() bool { return suite.Server.Ready() },
		time.Second,
		time.Millisecond,
	)
}

func (suite *LDAPTestSuite) TearDownSuite() {
	suite.Require().NoError(suite.Server.Stop())
}

func (suite *LDAPTestSuite) DialLDAP() (*goldap.Conn, error) {
	return goldap.DialURL("ldap://localhost:10389")
}

func (suite *LDAPTestSuite) TestMux_Bind() {
	suite.T().Run("SuccessfulBind", func(t *testing.T) {
		conn, err := suite.DialLDAP()
		suite.Require().NoError(err)
		defer conn.Close()

		err = conn.Bind("cn=alice,ou=people,dc=example,dc=org", "alice")
		assert.NoError(t, err)
	})

	suite.T().Run("SuccessfulAnonymousBind", func(t *testing.T) {
		conn, err := suite.DialLDAP()
		suite.Require().NoError(err)
		defer conn.Close()

		err = conn.UnauthenticatedBind("cn=bob,ou=people,dc=example,dc=org")
		assert.NoError(t, err)
	})

	suite.T().Run("UsernameDoesntExists", func(t *testing.T) {
		conn, err := suite.DialLDAP()
		suite.Require().NoError(err)
		defer conn.Close()

		err = conn.Bind("cn=eve,ou=people,dc=example,dc=org", "alice")
		assert.EqualError(t, err, "LDAP Result Code 49 \"Invalid Credentials\": ")
	})

	suite.T().Run("InvalidPassword", func(t *testing.T) {
		conn, err := suite.DialLDAP()
		suite.Require().NoError(err)
		defer conn.Close()

		err = conn.Bind("cn=alice,ou=people,dc=example,dc=org", "bob")
		assert.EqualError(t, err, "LDAP Result Code 49 \"Invalid Credentials\": ")
	})

	suite.T().Run("NoPasswordDefined", func(t *testing.T) {
		conn, err := suite.DialLDAP()
		suite.Require().NoError(err)
		defer conn.Close()

		err = conn.UnauthenticatedBind("cn=charlie,ou=people,dc=example,dc=org")
		assert.EqualError(t, err, "LDAP Result Code 49 \"Invalid Credentials\": ")
	})
}

func (suite *LDAPTestSuite) TestMux_Search() {
	conn, err := suite.DialLDAP()
	suite.Require().NoError(err)
	defer conn.Close()

	suite.T().Run("UnauthenticatedSearch", func(t *testing.T) {
		_, err = conn.Search(&goldap.SearchRequest{
			BaseDN: "dc=org",
			Scope:  goldap.ScopeWholeSubtree,
			Filter: "(cn=alice)",
		})
		assert.EqualError(t, err, "LDAP Result Code 123 \"Authorization Denied\": ")
	})

	// Bind as alice
	err = conn.Bind("cn=alice,ou=people,dc=example,dc=org", "alice")
	suite.Require().NoError(err)

	suite.T().Run("FindAlice", func(t *testing.T) {
		res, err := conn.Search(&goldap.SearchRequest{
			BaseDN: "dc=org",
			Scope:  goldap.ScopeWholeSubtree,
			Filter: "(cn=alice)",
		})
		require.NoError(t, err)

		assert.ElementsMatch(t,
			ResponseEntriesExpectation{
				{
					DN: "cn=alice,ou=people,dc=example,dc=org",
					Attributes: map[string][]string{
						"cn":           {"alice"},
						"objectClass":  {"person"},
						"userpassword": {"alice"},
					},
				},
			},
			ResponseEntriesHelper(res.Entries).Unwrap(),
		)
	})

	suite.T().Run("FindAllObjectclass", func(t *testing.T) {
		req := goldap.NewSearchRequest("dc=org", goldap.ScopeWholeSubtree, 0, 0, 0, false, "(objectClass=*)", nil, nil)
		res, err := conn.Search(req)
		require.NoError(t, err)

		assert.ElementsMatch(t,
			ResponseEntriesExpectation{
				{
					DN: "dc=example,dc=org",
					Attributes: map[string][]string{
						"dc":          {"example"},
						"objectClass": {"organization"},
					},
				},
				{
					DN: "cn=alice,ou=people,dc=example,dc=org",
					Attributes: map[string][]string{
						"cn":           {"alice"},
						"objectClass":  {"person"},
						"userpassword": {"alice"},
					},
				},
				{
					DN: "cn=charlie,ou=people,dc=example,dc=org",
					Attributes: map[string][]string{
						"cn":          {"charlie"},
						"objectClass": {"person"},
					},
				},
			},
			ResponseEntriesHelper(res.Entries).Unwrap(),
		)
	})

	suite.T().Run("FindAllOuOrCn", func(t *testing.T) {
		req := goldap.NewSearchRequest("dc=org", goldap.ScopeWholeSubtree, 0, 0, 0, false, "(|(ou=*)(cn=*))", nil, nil)
		res, err := conn.Search(req)
		require.NoError(t, err)

		assert.ElementsMatch(t,
			ResponseEntriesExpectation{
				{
					DN: "ou=people,dc=example,dc=org",
					Attributes: map[string][]string{
						"ou": {"people"},
					},
				},
				{
					DN: "cn=alice,ou=people,dc=example,dc=org",
					Attributes: map[string][]string{
						"cn":           {"alice"},
						"objectClass":  {"person"},
						"userpassword": {"alice"},
					},
				},
				{
					DN: "cn=charlie,ou=people,dc=example,dc=org",
					Attributes: map[string][]string{
						"cn":          {"charlie"},
						"objectClass": {"person"},
					},
				},
			},
			ResponseEntriesHelper(res.Entries).Unwrap(),
		)
	})

	suite.T().Run("InvalidDN", func(t *testing.T) {
		req := goldap.NewSearchRequest("dc=alice", goldap.ScopeWholeSubtree, 0, 0, 0, false, "(cn=alice)", nil, nil)
		_, err := conn.Search(req)

		assert.EqualError(t, err, "LDAP Result Code 32 \"No Such Object\": ")
	})

	suite.T().Run("InvalidScope", func(t *testing.T) {
		req := goldap.NewSearchRequest("dc=org", goldap.ScopeSingleLevel, 0, 0, 0, false, "(cn=alice)", nil, nil)
		res, err := conn.Search(req)
		require.NoError(t, err)

		assert.Len(t, res.Entries, 0)
	})
}

func (suite *LDAPTestSuite) TestMux_Add() {
	conn, err := suite.DialLDAP()
	suite.Require().NoError(err)
	defer conn.Close()

	err = conn.Bind("cn=alice,ou=people,dc=example,dc=org", "alice")
	suite.Require().NoError(err)

	suite.T().Run("SuccessfulAdd", func(t *testing.T) {
		req := goldap.NewAddRequest("cn=alice,ou=people,dc=example,dc=org", nil)
		err := conn.Add(req)
		assert.EqualError(t, err, "LDAP Result Code 53 \"Unwilling To Perform\": yaLDAP only support Bind and Search operations")
	})
}

func (suite *LDAPTestSuite) TestMux_Modify() {
	conn, err := suite.DialLDAP()
	suite.Require().NoError(err)
	defer conn.Close()

	err = conn.Bind("cn=alice,ou=people,dc=example,dc=org", "alice")
	suite.Require().NoError(err)

	suite.T().Run("SuccessfulModify", func(t *testing.T) {
		req := goldap.NewModifyRequest("cn=alice,ou=people,dc=example,dc=org", nil)
		err := conn.Modify(req)
		assert.EqualError(t, err, "LDAP Result Code 53 \"Unwilling To Perform\": yaLDAP only support Bind and Search operations")
	})
}

func (suite *LDAPTestSuite) TestMux_Delete() {
	conn, err := suite.DialLDAP()
	suite.Require().NoError(err)
	defer conn.Close()

	err = conn.Bind("cn=alice,ou=people,dc=example,dc=org", "alice")
	suite.Require().NoError(err)

	suite.T().Run("SuccessfulDelete", func(t *testing.T) {
		req := goldap.NewDelRequest("cn=alice,ou=people,dc=example,dc=org", nil)
		err := conn.Del(req)
		assert.EqualError(t, err, "LDAP Result Code 53 \"Unwilling To Perform\": yaLDAP only support Bind and Search operations")
	})
}

func TestLDAPSuite(t *testing.T) { suite.Run(t, new(LDAPTestSuite)) }

func (r ResponseEntryHelper) Unwrap() ResponseEntryExpectation {
	expect := ResponseEntryExpectation{
		DN:         r.DN,
		Attributes: map[string][]string{},
	}

	for _, attr := range r.Attributes {
		expect.Attributes[attr.Name] = attr.Values
	}
	return expect
}

func (r ResponseEntriesHelper) Unwrap() ResponseEntriesExpectation {
	expect := ResponseEntriesExpectation{}
	for _, entry := range r {
		expect = append(expect, ResponseEntryHelper{entry}.Unwrap())
	}
	return expect
}
