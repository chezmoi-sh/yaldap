package main

import (
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestXX(t *testing.T) {
	//td := testdirectory.Start(t,
	//	testdirectory.WithNoTLS(t),
	//	testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: false}),
	//)
	//td.SetUsers(testdirectory.NewUsers(t, []string{"alice"})...)

	ldapURL := "ldap://localhost:10389"
	//ldapURL := "ldap://localhost:389"
	l, err := ldap.DialURL(ldapURL)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	//l := td.Conn()

	err = l.Bind("uid=alice,ou=people,cn=example,dc=org", "passord")
	//err = l.Bind("cn=admin,dc=example,dc=org", "admin")
	if err != nil {
		t.Fatalf(err.Error())
	}

	user := "alice"
	baseDN := "dc=example,dc=org"
	filter := fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(user))
	filter = "(&(|(!memberOf=cn=fire*,OU=*Atlassian* Groups,dc=xxxx,dc=com)(memberOf=*cn=wind,OU=Atlassian Groups,dc=xxxx,dc=com*)(memberOf=cn=water,OU=Atlassian Groups,dc=xxxx,dc=com)(memberOf=cn=heart,OU=Atlassian Groups,dc=xxxx,dc=xxxx))(objectCategory~=Person)(sAMAccountName=*)(mail=*))"
	filter = "(|(cn=*)(ou=*))"
	filter = "(objectClass=*)"

	// Filters must start and finish with ()!
	searchReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{}, []ldap.Control{})

	result, err := l.Search(searchReq)
	if err != nil {
		t.Fatalf("failed to query LDAP: %s", err)
	}

	t.Log("Got", len(result.Entries), "search results")
	for _, entry := range result.Entries {
		for _, attribute := range entry.Attributes {
			t.Logf("%s: %s => %#v", entry.DN, attribute.Name, attribute.Values)
		}
	}
}
