package yamldir_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ldap "github.com/xunleii/yaldap/pkg/ldap/directory"
	yamldir "github.com/xunleii/yaldap/pkg/ldap/directory/yaml"
)

func TestFixture_Basic(t *testing.T) {
	directory, err := yamldir.NewDirectory("fixtures/basic.yaml")
	require.NoError(t, err)

	t.Run("dc=org", func(t *testing.T) {
		obj := directory.BaseDN("dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"dc": {"org"},
			},
			obj.Attributes(),
		)
	})

	t.Run("ou=group,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"dc": {"example"},
			},
			obj.Attributes(),
		)
	})

	t.Run("ou=group,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("ou=group,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"ou": {"group"},
			},
			obj.Attributes(),
		)
	})

	t.Run("cn=owner,ou=group,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=owner,ou=group,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":          {"owner"},
				"objectClass": {"posixGroup"},
				"gidNumber":   {"1000"},
				"description": {"Organization owners"},
				"memberUid":   {"alice"},
			},
			obj.Attributes(),
		)
	})

	t.Run("cn=dev,ou=group,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=dev,ou=group,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":          {"dev"},
				"objectClass": {"posixGroup"},
				"gidNumber":   {"1001"},
				"description": {"Organization developers"},
				"memberUid":   {"bob", "charlie"},
			},
			obj.Attributes(),
		)
	})

	t.Run("cn=qa,ou=group,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=qa,ou=group,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":          {"qa"},
				"objectClass": {"posixGroup"},
				"gidNumber":   {"1002"},
				"memberUid":   {"charlie", "eve"},
			},
			obj.Attributes(),
		)
	})

	t.Run("cn=ok,ou=group,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=ok,ou=group,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":          {"ok"},
				"objectClass": {"posixGroup"},
				"gidNumber":   {"1003"},
				"description": {"Dummy group"},
				"memberUid":   {"alice"},
			},
			obj.Attributes(),
		)
	})

	t.Run("cn=admin,ou=group,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("c=global,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"c": {"global"},
			},
			obj.Attributes(),
		)
	})

	t.Run("ou=people,c=global,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("ou=people,c=global,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"ou": {"people"},
			},
			obj.Attributes(),
		)
	})

	t.Run("cn=alice,ou=people,c=global,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=alice,ou=people,c=global,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":            {"alice"},
				"objectClass":   {"posixAccount", "UserMail"},
				"description":   {"Main organization admin"},
				"uid":           {"alice"},
				"uidNumber":     {"1000"},
				"gidNumber":     {"1000"},
				"loginShell":    {"/bin/bash"},
				"homeDirectory": {"/home/alice"},
				"userPassword":  {"alice"},
				"usermail":      {"alice@example.org"},
			},
			obj.Attributes(),
		)
		assert.True(t, obj.Bind("alice"))
		assert.True(t, obj.CanSearchOn("dc=org"))
	})

	t.Run("cn=bob,ou=people,c=global,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=bob,ou=people,c=global,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":            {"bob"},
				"objectClass":   {"posixAccount"},
				"uid":           {"bob"},
				"homeDirectory": {"/home/bob"},
				"uidNumber":     {"1001"},
				"gidNumber":     {"1001"},
				"userPassword":  {"bob"},
			},
			obj.Attributes(),
		)
		assert.True(t, obj.Bind("bob"))
		assert.False(t, obj.CanSearchOn("dc=org"))
		assert.True(t, obj.CanSearchOn("ou=group,dc=example,dc=org"))
	})

	t.Run("cn=charlie,ou=people,c=global,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("c=fr,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"c": {"fr"},
			},
			obj.Attributes(),
		)
	})

	t.Run("ou=people,c=fr,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("ou=people,c=fr,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"ou": {"people"},
			},
			obj.Attributes(),
		)
	})

	t.Run("cn=charlie,ou=people,c=fr,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=charlie,ou=people,c=fr,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":            {"charlie"},
				"objectClass":   {"posixAccount"},
				"uid":           {"charlie"},
				"homeDirectory": {"/home/charlie"},
				"uidNumber":     {"1100"},
				"gidNumber":     {"1001"},
				"userPassword":  {"charlie"},
			},
			obj.Attributes(),
		)
		assert.True(t, obj.Bind("charlie"))
		assert.False(t, obj.CanSearchOn("dc=org"))
		assert.True(t, obj.CanSearchOn("ou=group,dc=example,dc=org"))
		x := obj.CanSearchOn("cn=admin,ou=group,dc=example,dc=org")
		_ = x
		assert.False(t, obj.CanSearchOn("cn=admin,ou=group,dc=example,dc=org"))
	})

	t.Run("c=uk,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("c=uk,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"c": {"uk"},
			},
			obj.Attributes(),
		)
	})

	t.Run("ou=people,c=uk,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("ou=people,c=uk,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"ou": {"people"},
			},
			obj.Attributes(),
		)
	})

	t.Run("cn=eve,ou=people,c=uk,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=eve,ou=people,c=uk,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":            {"eve"},
				"objectClass":   {"posixAccount"},
				"uid":           {"eve"},
				"homeDirectory": {"/home/eve"},
				"uidNumber":     {"1003"},
				"gidNumber":     {"1002"},
				"userPassword":  {"eve"},
			},
			obj.Attributes(),
		)
		assert.False(t, obj.Bind("eve"))
		assert.False(t, obj.CanSearchOn("dc=org"))
		assert.False(t, obj.CanSearchOn("ou=group,dc=example,dc=org"))
		assert.False(t, obj.CanSearchOn("c=fr,dc=example,dc=org"))
		assert.False(t, obj.CanSearchOn("cn=admin,ou=group,dc=example,dc=org"))
	})
}
