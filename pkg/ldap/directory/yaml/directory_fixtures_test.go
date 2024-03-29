package yamldir_test

import (
	"testing"

	ldap "github.com/chezmoi-sh/yaldap/pkg/ldap/directory"
	yamldir "github.com/chezmoi-sh/yaldap/pkg/ldap/directory/yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFixture_Basic(t *testing.T) {
	directory, err := yamldir.NewDirectory("fixtures/basic.yaml")
	require.NoError(t, err)

	t.Run("dc=org", func(t *testing.T) {
		obj := directory.BaseDN("dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"dc":          {"org"},
				"objectClass": {"top", "domain"},
			},
			obj.Attributes(),
		)
	})

	t.Run("dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"dc":          {"example"},
				"objectClass": {"domain"},
			},
			obj.Attributes(),
		)
	})

	t.Run("ou=group,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("ou=group,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"ou":          {"group"},
				"objectClass": {"top"},
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
		obj := directory.BaseDN("c=fr,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"c":           {"fr"},
				"objectClass": {"top", "country"},
			},
			obj.Attributes(),
		)
	})

	t.Run("ou=people,c=fr,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("ou=people,c=fr,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"ou":          {"people"},
				"objectClass": {"top"},
			},
			obj.Attributes(),
		)
	})

	t.Run("cn=alice,ou=people,c=fr,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=alice,ou=people,c=fr,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":            {"alice"},
				"objectClass":   {"posixAccount"},
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
		isBind, err := obj.Bind("alice")
		require.NoError(t, err)
		assert.True(t, isBind)
		assert.True(t, obj.CanSearchOn("dc=org"))
	})

	t.Run("cn=bob,ou=people,c=fr,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=bob,ou=people,c=fr,dc=example,dc=org")
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
		isBind, err := obj.Bind("bob")
		require.NoError(t, err)
		assert.True(t, isBind)
		assert.False(t, obj.CanSearchOn("dc=org"))
		assert.True(t, obj.CanSearchOn("ou=group,dc=example,dc=org"))
	})

	t.Run("cn=charlie,ou=people,c=fr,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("c=fr,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"c":           {"fr"},
				"objectClass": {"top", "country"},
			},
			obj.Attributes(),
		)
	})

	t.Run("ou=people,c=fr,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("ou=people,c=fr,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"ou":          {"people"},
				"objectClass": {"top"},
			},
			obj.Attributes(),
		)
	})

	t.Run("cn=charlie,ou=people,c=de,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=charlie,ou=people,c=de,dc=example,dc=org")
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
		isBind, err := obj.Bind("charlie")
		require.NoError(t, err)
		assert.True(t, isBind)
		assert.False(t, obj.CanSearchOn("dc=org"))
		assert.True(t, obj.CanSearchOn("ou=group,dc=example,dc=org"))
		assert.False(t, obj.CanSearchOn("cn=owner,ou=group,dc=example,dc=org"))
	})

	t.Run("c=uk,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("c=uk,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"c":           {"uk"},
				"objectClass": {"top", "country"},
			},
			obj.Attributes(),
		)
	})

	t.Run("ou=people,c=uk,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("ou=people,c=uk,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"ou":          {"people"},
				"objectClass": {"top"},
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
		isBind, err := obj.Bind("eve")
		require.NoError(t, err)
		assert.False(t, isBind)
		assert.False(t, obj.CanSearchOn("dc=org"))
		assert.False(t, obj.CanSearchOn("ou=group,dc=example,dc=org"))
		assert.False(t, obj.CanSearchOn("c=fr,dc=example,dc=org"))
		assert.False(t, obj.CanSearchOn("cn=admin,ou=group,dc=example,dc=org"))
	})
}

func TestFixture_Templated(t *testing.T) {
	directory, err := yamldir.NewDirectory("fixtures/templated.yaml")
	require.NoError(t, err)

	t.Run("dc=org", func(t *testing.T) {
		obj := directory.BaseDN("dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"dc":          {"org"},
				"objectClass": {"top", "domain"},
			},
			obj.Attributes(),
		)
	})

	t.Run("dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"dc":          {"example"},
				"objectClass": {"domain"},
			},
			obj.Attributes(),
		)
	})

	t.Run("ou=group,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("ou=group,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"ou":          {"group"},
				"objectClass": {"top"},
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
				"memberUid":   {"alice", "bob", "charlie", "eve"},
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
				"description": {"Organization quality assurance"},
				"memberUid":   {"eve"},
			},
			obj.Attributes(),
		)
	})

	t.Run("ou=people,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("ou=people,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"ou":          {"people"},
				"objectClass": {"top"},
			},
			obj.Attributes(),
		)
	})

	t.Run("cn=bind,ou=people,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=bind,ou=people,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":          {"bind"},
				"objectClass": {"top"},
				"password":    {"bind"},
			},
			obj.Attributes(),
		)
		isBind, err := obj.Bind("bind")
		require.NoError(t, err)
		assert.True(t, isBind)
		assert.True(t, obj.CanSearchOn("dc=org"))
	})

	t.Run("cn=alice,ou=people,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=alice,ou=people,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":            {"alice"},
				"objectClass":   {"posixAccount"},
				"description":   {"User alice"},
				"uid":           {"alice"},
				"uidNumber":     {"1000"},
				"gidNumber":     {"1000"},
				"loginShell":    {"/bin/bash"},
				"homeDirectory": {"/home/alice"},
				"userPassword":  {"alice"},
				"userMail":      {"alice@example.org"},
			},
			obj.Attributes(),
		)

		isBind, err := obj.Bind("alice")
		require.NoError(t, err)
		assert.True(t, isBind)
		assert.False(t, obj.CanSearchOn("dc=org"))
		assert.True(t, obj.CanSearchOn("cn=alice,ou=people,dc=example,dc=org"))
	})

	t.Run("cn=bob,ou=people,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=bob,ou=people,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":            {"bob"},
				"objectClass":   {"posixAccount"},
				"description":   {"User bob"},
				"uid":           {"bob"},
				"homeDirectory": {"/home/bob"},
				"uidNumber":     {"1001"},
				"gidNumber":     {"1001"},
				"loginShell":    {"/bin/bash"},
				"userPassword":  {"bob"},
				"userMail":      {"bob@example.org"},
			},
			obj.Attributes(),
		)
		isBind, err := obj.Bind("bob")
		require.NoError(t, err)
		assert.True(t, isBind)
		assert.False(t, obj.CanSearchOn("dc=org"))
		assert.True(t, obj.CanSearchOn("cn=bob,ou=people,dc=example,dc=org"))
	})

	t.Run("cn=charlie,ou=people,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=charlie,ou=people,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":            {"charlie"},
				"objectClass":   {"posixAccount"},
				"description":   {"User charlie"},
				"uid":           {"charlie"},
				"homeDirectory": {"/home/charlie"},
				"uidNumber":     {"1002"},
				"gidNumber":     {"1001"},
				"loginShell":    {"/bin/bash"},
				"userPassword":  {"charlie"},
				"userMail":      {"charlie@example.org"},
			},
			obj.Attributes(),
		)
		isBind, err := obj.Bind("charlie")
		require.NoError(t, err)
		assert.True(t, isBind)
		assert.False(t, obj.CanSearchOn("dc=org"))
		assert.True(t, obj.CanSearchOn("cn=charlie,ou=people,dc=example,dc=org"))
	})

	t.Run("cn=eve,ou=people,dc=example,dc=org", func(t *testing.T) {
		obj := directory.BaseDN("cn=eve,ou=people,dc=example,dc=org")
		require.NotNil(t, obj)
		assert.Equal(t,
			ldap.Attributes{
				"cn":            {"eve"},
				"objectClass":   {"posixAccount"},
				"description":   {"User eve"},
				"uid":           {"eve"},
				"homeDirectory": {"/home/eve"},
				"uidNumber":     {"1003"},
				"gidNumber":     {"1001"},
				"loginShell":    {"/bin/bash"},
				"userPassword":  {"eve"},
				"userMail":      {"eve@example.org"},
			},
			obj.Attributes(),
		)
		isBind, err := obj.Bind("eve")
		require.NoError(t, err)
		assert.True(t, isBind)
		assert.False(t, obj.CanSearchOn("dc=org"))
		assert.True(t, obj.CanSearchOn("cn=eve,ou=people,dc=example,dc=org"))
	})
}
