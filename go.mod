module github.com/xunleii/yaldap

go 1.21

// TODO: remove this once the following issue is resolved: https://github.com/jimlambrt/gldap/pull/58
replace github.com/jimlambrt/gldap => github.com/xunleii/gldap v0.1.10

require (
	github.com/alecthomas/kong v0.8.1
	github.com/go-asn1-ber/asn1-ber v1.5.5
	github.com/go-dedup/metaphone v0.0.0-20141025200009-5cea56e8d200
	github.com/go-ldap/ldap/v3 v3.4.6
	github.com/jimlambrt/gldap v0.1.9
	github.com/madflojo/testcerts v1.1.1
	github.com/moznion/go-optional v0.11.0
	github.com/puzpuzpuz/xsync/v3 v3.0.2
	github.com/stretchr/testify v1.8.4
	golang.org/x/exp v0.0.0-20231214170342-aacd6d4b4611
	golang.org/x/sync v0.1.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/hashicorp/go-hclog v1.6.2
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
)
