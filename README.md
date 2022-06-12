# yaLDAP: yet another LDAP
yaLDAP is an easy-to-use LDAP server using YAML file as directory definition.

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/xunleii/yaldap)
[![Go](https://github.com/xunleii/yaldap/actions/workflows/go.yaml/badge.svg?branch=main)](https://github.com/xunleii/yaldap/actions/workflows/go.yaml)
[![Language grade: Go](https://img.shields.io/lgtm/grade/go/g/xunleii/yaldap.svg?logo=lgtm)](https://lgtm.com/projects/g/xunleii/yaldap/context:go)
[![codecov](https://codecov.io/gh/xunleii/yaldap/branch/main/graph/badge.svg?token=20J4XPYH1H)](https://codecov.io/gh/xunleii/yaldap)
[![Go Report Card](https://goreportcard.com/badge/github.com/xunleii/yaldap)](https://goreportcard.com/report/github.com/xunleii/yaldap)

_Sometimes, we just need a simple LDAP compatible server to store user/group information and other information.  
For this purpose, many simple LDAP server exists and manage user/group in a better way than yaLDAP. However, no one can 
have a fully customisable LDAP directory that can be used to store information or to follow a specific directory structure.
**I don't recommend to use this project for other thing than dev or homelab purpose; this LDAP server is not _(yet)_ 
compliant with the LDAP RFCs.**_

## Usage

## Configuration

### YAML
yaLDAP can be configured using an YAML file to describe the LDAP directory.

See [/pkg/ldap/yaml](/pkg/ldap/yaml/) for more information.

#### Example
```yaml
dc:org:
  dc:example:
    ou:group:
      cn:owner:
        .#objectclass: posixGroup
        .@gidNumber: 1000
        .@description: Organization owners
        .@memberUid: [1000]
      cn:dev:
        .#objectclass: posixGroup
        .@gidNumber: 1001
        .@description: Organization developers
        .@memberUid: [1001, 1100]
      cn:qa:
        .#objectclass: posixGroup
        .@gidNumber: 1002
        .@memberUid: [1200]

    c:global:
      ou:people:
        cn:alice:
          .#bindPassword: userPassword
          .#allowDN: dc=org # allow alice to request everything

          .#objectclass: posixAccount
          .@description: Main organization admin
          .@uid: alice
          .@uidNumber: 1000
          .@gidNumber: 1000
          .@homeDirectory: /home/alice
          .@loginShell: /bin/bash
          .@userPassword: alice
        cn:bob:
          .#bindPassword: userPassword
          .#allowDN: ou=group,dc=example,dc=org # allow bob request only for user groups

          .#objectclass: posixAccount
          .@uid: bob
          .@uidNumber: 1001
          .@gidNumber: 1001
          .@homeDirectory: /home/bob
          .@loginShell: /bin/bash
          .@userPassword: bob

    c:fr:
      ou:people:
        cn:charlie:
          .#bindPassword: userPassword
          .#allowDN: [ou=group,dc=example,dc=org, c=fr,dc=example,dc=org] # allow charlie request only for user groups & fr peoples ...
          .#denyDN: cn=admin,ou=group,dc=example,dc=org # ...but deny access to owner group

          .#objectclass: posixAccount
          .@uid: bob
          .@uidNumber: 1100
          .@gidNumber: 1001
          .@homeDirectory: /home/charlie
          .@loginShell: /bin/bash
          .@userPassword: charlie

    c:uk: #dn: c=uk,dc=example,dc=org
      ou:people: #dn: ou=people,c=fr,dc=example,dc=org
        cn:eve: #dn: cn=eve,ou=people,c=uk,dc=example,dc=org
          #NOTE: eve can't make any LDAP request (not .#bindPassword property)
          .#objectclass: posixAccount
          .@uid: bob
          .@uidNumber: 1200
          .@gidNumber: 1002
          .@homeDirectory: /home/charlie
          .@loginShell: /bin/bash
          .@userPassword: eve
```

## Contribution