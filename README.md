# yaLDAP: yet another LDAP

yaLDAP is an easy-to-use LDAP server using YAML file as directory definition.

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/chezmoi-sh/yaldap)
[![Test code (Go)](https://github.com/chezmoi-sh/yaldap/actions/workflows/merge_group,pull_request.go.test.yaml/badge.svg?event=push)](https://github.com/chezmoi-sh/yaldap/actions/workflows/merge_group,pull_request.go.test.yaml)
[![CodeQL](https://github.com/chezmoi-sh/yaldap/actions/workflows/pull_request,push,schedule.codeql.yaml/badge.svg)](https://github.com/chezmoi-sh/yaldap/actions/workflows/pull_request,push,schedule.codeql.yaml)
[![codecov](https://codecov.io/gh/chezmoi-sh/yaldap/branch/main/graph/badge.svg?token=20J4XPYH1H)](https://codecov.io/gh/chezmoi-sh/yaldap)
[![Go Report Card](https://goreportcard.com/badge/github.com/chezmoi-sh/yaldap)](https://goreportcard.com/report/github.com/chezmoi-sh/yaldap)

_Sometimes, we just need a simple LDAP compatible server to store user/group information and other information.  
For this purpose, many simple LDAP server exists and manage user/group in a better way than yaLDAP. However, no one can
have a fully customisable LDAP directory that can be used to store information or to follow a specific directory structure._  
**_I don't recommend to use this project for other thing than dev or homelab purpose; this LDAP server is not _(yet)_
compliant with the LDAP RFCs._**

## Usage

## Configuration

### YAML

yaLDAP can be configured using an YAML file to describe the LDAP directory.

See [/pkg/ldap/yaml](pkg/ldap/directory/yaml/README.md) for more information.

#### Example

```yaml
dc:org: #dn: dc=org
  dc:example: #dn: dc=example,dc=org
    ou:group: #dn: ou=group,dc=example,dc=org
      cn:owner: &test #dn: cn=admin,ou=group,dc=example,dc=org
        objectClass: posixGroup
        gidNumber: 1000
        description: Organization owners
        memberUid: [alice]
      cn:dev: #dn: cn=dev,ou=group,dc=example,dc=org
        objectClass: posixGroup
        gidNumber: 1001
        description: Organization developers
        memberUid: [bob, charlie]
      cn:qa: #dn: cn=qa,ou=group,dc=example,dc=org
        objectClass: posixGroup
        gidNumber: 1002
        memberUid: [charlie, eve]
      cn:ok: #dn: cn=ok,ou=group,dc=example,dc=org
        <<: *test
        gidNumber: 1003
        description: Dummy group
        # memberUid: [alice]

    c:global: #dn: c=global,dc=example,dc=org
      ou:people: #dn: ou=people,c=global,dc=example,dc=org
        cn:alice: #dn: cn=alice,ou=people,c=global,dc=example,dc=org
          objectClass: [posixAccount, UserMail]
          .#acl:
            - !!ldap/acl:allow-on dc=org # allow alice to request everything

          description: Main organization admin
          uid: alice
          uidNumber: 1000
          gidNumber: 1000
          loginShell: /bin/bash
          homeDirectory: /home/alice
          userPassword: !!ldap/bind:password alice
          usermail: alice@example.org

        cn:bob: #dn: cn=bob,ou=people,c=global,dc=example,dc=org
          objectClass: posixAccount
          .#acl:
            - !!ldap/acl:allow-on ou=group,dc=example,dc=org # allow bob request only for user groups

          uid: bob
          homeDirectory: /home/bob
          uidNumber: 1001
          gidNumber: 1001
          userPassword: !!ldap/bind:password bob

    c:fr: #dn: c=fr,dc=example,dc=org
      ou:people: #dn: ou=people,c=fr,dc=example,dc=org
        cn:charlie: #dn: cn=charlie,ou=people,c=fr,dc=example,dc=org
          objectClass: posixAccount
          .#acl:
            - !!ldap/acl:allow-on ou=group,dc=example,dc=org # allow charlie request for all groups...
            - !!ldap/acl:deny-on cn=admin,ou=group,dc=example,dc=org # ...but  to owner group

          uid: charlie
          homeDirectory: /home/charlie
          uidNumber: 1100
          gidNumber: 1001
          userPassword: !!ldap/bind:password charlie

    c:uk: #dn: c=uk,dc=example,dc=org
      ou:people: #dn: ou=people,c=fr,dc=example,dc=org
        cn:eve: #dn: cn=eve,ou=people,c=uk,dc=example,dc=org
          objectClass: posixAccount
          #NOTE: eve can't make any LDAP request (no !!ldap/bind:password field)
          uid: eve
          homeDirectory: /home/eve
          uidNumber: 1003
          gidNumber: 1002
          userPassword: eve
```

## Contribution
