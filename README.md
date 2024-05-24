<!-- markdownlint-disable MD033 -->
<h1 align="center">
  chezmoi.sh · yaLDAP
  <br/>
  <img src="assets/9f0b3036-377c-4c59-a1aa-b7676401b305.png" alt="White Malamut puppy as logo" height="250px">
</h1>

<h4 align="center">yaLDAP - Yet Another LDAP</h4>

<div align="center">

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/chezmoi-sh/yaldap)
[![Test code (Go)](https://github.com/chezmoi-sh/yaldap/actions/workflows/merge_group,pull_request.go.test.yaml/badge.svg?event=push)](https://github.com/chezmoi-sh/yaldap/actions/workflows/merge_group,pull_request.go.test.yaml)
[![codecov](https://codecov.io/gh/chezmoi-sh/yaldap/branch/main/graph/badge.svg?token=20J4XPYH1H)](https://codecov.io/gh/chezmoi-sh/yaldap)
[![Go Report Card](https://goreportcard.com/badge/github.com/chezmoi-sh/yaldap)](https://goreportcard.com/report/github.com/chezmoi-sh/yaldap)

[![License](https://img.shields.io/badge/license-AGPL%20v3-blue?logo=git&logoColor=white&logoWidth=20)](LICENSE)

<a href="#information_source-about">About</a> ·
<a href="#-getting-started">Getting Started</a> ·
<a href="#arrow_forward-how-to-use-yaldap">How to use yaLDAP</a> ·
<a href="#wrench-configuration">Configuration</a> ·
<a href="#octocat-contribution">Contribution</a> ·
<a href="#ledger-license">License</a>

</div>

---

<!-- markdownlint-enable MD033 -->


## :information_source: About

yaLDAP is an easy-to-use LDAP server using YAML file as directory definition.


_Sometimes, we just need a simple LDAP compatible server to store user/group information and other information.  
For this purpose, many simple LDAP server exists and manage user/group in a better way than yaLDAP. However, no one can
have a fully customisable LDAP directory that can be used to store information or to follow a specific directory structure. 
**This is why yaLDAP exists: to provide a simple LDAP server that can be used to store any kind of information in a
customisable way.**_

> [!CAUTION]
> _I don't recommend to use this project for other thing than dev or homelab purpose; this LDAP server is not _(yet)_
> compliant with the LDAP RFCs._

## 🚀 Getting Started

### Installing

> [!NOTE]
> yaLDAP is still in development and is not yet available other than as a Go installable package.

To start using yaLDAP, you need to install Go 1.20 or above. It is provided as a CLI directly installable from
Go, so you can install it using

```sh
go install github.com/chezmoi-sh/yaldap/cmd/yaldap@latest
```

## :arrow_forward: How to use yaLDAP

To run yaLDAP, you need to provide a backend to use. Currently, only the YAML backend is available.
For example, to run yaLDAP with the YAML backend, you can use the following command:

```sh
yaldap run --backend.name yaml --backend.url <path-to-yaml-file>
```

Also, yaLDAP is ship with a set of tools that can be used to manage some part of the LDAP configuration, like hashing.
For example, to hash a password using bcrypt, you can use the following command:

```sh
echo -n "password" | yaldap tools hash bcrypt --rounds 10 -
$bcrypt$v=0$r=10$$24326124313024504b374745686b483639377870322f37367676397965792e5155752f5763383941532f44476d385a4a725555437637536b5133684b
```

For more information about the tools, you can use the following command:

```sh
yaldap tools --help
```

## :wrench: Configuration

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

## :octocat: Contribution

If you want to contribute to yaLDAP, you can follow the [CONTRIBUTING.md](CONTRIBUTING.md) file.

## :ledger: License

yaLDAP is licensed under the AGPL v3 License. See the [LICENSE](LICENSE) file for more information.