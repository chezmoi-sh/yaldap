# LDAP directory implementation for YAML format

## Why using YAML?
Nowadays, I found that `YAML` is overused to configure things that sometimes requires more simple markup languages (`ini`, `txt`, ...),
or mode specific DSL (like `hcl`). Of course, `YAML` is now a well known markup language and can be easily use by almost
everyone.
However, I personally chose `YAML` because it gives me a better representation of the directory structure;
I picture an LDAP directory as a file directory, with folders (`containers`) and files (`leafs`). The fact that `YAML`
uses indentation to define the depth of a field reminds me the `tree` command and helps me a lot in the global
representation of the LDAP directory.

## Syntax
In order to manage several kind of information (attributes, properties & children) inside the same YAML object, we will
use dotted prefix.

```bnf
<attribute> ::= ".@" <word> ":"
<property> ::= ".#" <word> ":"
<children> ::= <x500_attrType> ":" <word> ":"
<x500_attrType> ::= (<lower> | <upper>)+
<word> ::= (<lower> | <upper> | <digit>)+
<upper> ::= "A" | "B" | "C" | "D" | "E" | "F" | "G" | "H" | "I" | "J" | "K" | "L" | "M" | "N" | "O" | "P" | "Q" | "R" | "S" | "T" | "U" | "V" | "W" | "X" | "Y" | "Z"
<lower> ::= "a" | "b" | "c" | "d" | "e" | "f" | "g" | "h" | "i" | "j" | "k" | "l" | "m" | "n" | "o" | "p" | "q" | "r" | "s" | "t" | "u" | "v" | "w" | "x" | "y" | "z"
<digit> ::= "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "0"
```

> _**NOTE:** I recommend to use well known X.500 AttributeTypes like `cn` or `dc`, but everything following the BNF
>        rule should work_
> _**NOTE²:** the attribute type will be automatically injected inside the LDAP object as attribute; for example, `cn:alice`
>         will create an attribute `cn` with `alice` as value inside the object `cn=alice`_
> _**NOTE³:** the BNF rules can be tested [here](https://bnfplayground.pauliankline.com/?bnf=%3Cattribute%3E%20%3A%3A%3D%20%22.%40%22%20%3Cword%3E%20%22%3A%22%0A%3Cproperty%3E%20%3A%3A%3D%20%22.%23%22%20%3Cword%3E%20%22%3A%22%0A%3Cchildren%3E%20%3A%3A%3D%20%3Cx500_attrType%3E%20%22%3A%22%20%3Cword%3E%20%22%3A%22%0A%0A%3Cx500_attrType%3E%20%3A%3A%3D%20(%3Clower%3E%20%7C%20%3Cupper%3E)%2B%0A%3Cword%3E%20%3A%3A%3D%20(%3Clower%3E%20%7C%20%3Cupper%3E%20%7C%20%3Cdigit%3E)%2B%0A%3Cupper%3E%20%3A%3A%3D%20%22A%22%20%7C%20%22B%22%20%7C%20%22C%22%20%7C%20%22D%22%20%7C%20%22E%22%20%7C%20%22F%22%20%7C%20%22G%22%20%7C%20%22H%22%20%7C%20%22I%22%20%7C%20%22J%22%20%7C%20%22K%22%20%7C%20%22L%22%20%7C%20%22M%22%20%7C%20%22N%22%20%7C%20%22O%22%20%7C%20%22P%22%20%7C%20%22Q%22%20%7C%20%22R%22%20%7C%20%22S%22%20%7C%20%22T%22%20%7C%20%22U%22%20%7C%20%22V%22%20%7C%20%22W%22%20%7C%20%22X%22%20%7C%20%22Y%22%20%7C%20%22Z%22%0A%3Clower%3E%20%3A%3A%3D%20%22a%22%20%7C%20%22b%22%20%7C%20%22c%22%20%7C%20%22d%22%20%7C%20%22e%22%20%7C%20%22f%22%20%7C%20%22g%22%20%7C%20%22h%22%20%7C%20%22i%22%20%7C%20%22j%22%20%7C%20%22k%22%20%7C%20%22l%22%20%7C%20%22m%22%20%7C%20%22n%22%20%7C%20%22o%22%20%7C%20%22p%22%20%7C%20%22q%22%20%7C%20%22r%22%20%7C%20%22s%22%20%7C%20%22t%22%20%7C%20%22u%22%20%7C%20%22v%22%20%7C%20%22w%22%20%7C%20%22x%22%20%7C%20%22y%22%20%7C%20%22z%22%0A%3Cdigit%3E%20%3A%3A%3D%20%221%22%20%7C%20%222%22%20%7C%20%223%22%20%7C%20%224%22%20%7C%20%225%22%20%7C%20%226%22%20%7C%20%227%22%20%7C%20%228%22%20%7C%20%229%22%20%7C%20%220%22&name=yaLDAP%20YAML%20keys)_

### Kind of fields:
- `children`: represent an LDAP children object (or sub-object). The key should contain an LDAP attribute type and its
              value.
- `attribute`: represent an LDAP attribute. The attribute name **MUST BE** prefixed by `.@`.
- `property`: represent an internal property of the object. These properties are used by the YAML LDAP directory
              implementation to manage some capabilities and/or metadata. Properties are not case-sensitive.
  - `.#objectclass`: define the current object class. This property will generate the `objectClass` attribute but could
                     be used to generate some metadata base on which attribute are used (RFC).
  - `.#bindPassword`: define which LDAP attribute should be used as `BIND` password.
  - `.#allowDN`: define which LDAP object could be returned during an LDAP `SEARCH` request. It could be a container; in
                 this case, all children will be allowed too.
  - `.#denyDN`: like `.#allowDN` but to force the `deny` policy on specific LDAP object.

> _**NOTE:** all DN are denied by default during an LDAP `SEARCH` request._
> _**NOTE²:** `.#allowDN` and `.#denyDN` can be used together; the most precise DN is, the highest the rule priority will be._

### Example
```yaml
dc:org: #dn: dc=org
  dc:example: #dn: dc=example,dc=org
    ou:group: #dn: ou=group,dc=example,dc=org
      cn:owner: #dn: cn=admin,ou=group,dc=example,dc=org
        .#objectclass: posixGroup
        .@gidNumber: 1000
        .@description: Organization owners
        .@memberUid: {{ LdapSearch '(gidNumber=1000)' | LdapAttribute uidNumber }} #RFC(02): not yet implemented
      cn:dev: #dn: cn=dev,ou=group,dc=example,dc=org
        .#objectclass: posixGroup
        .@gidNumber: 1001
        .@description: Organization developers
        .@memberUid: {{ LdapSearch '(gidNumber=1001)' | LdapAttribute uidNumber }} #RFC(02): not yet implemented
      cn:qa: #dn: cn=qa,ou=group,dc=example,dc=org
        .#objectclass: posixGroup
        .@gidNumber: 1002
        .@memberUid: {{ LdapSearch '(gidNumber=1002)' | LdapAttribute uidNumber }} #RFC(02): not yet implemented

    c:global: #dn: c=global,dc=example,dc=org
      ou:people: #dn: ou=people,c=global,dc=example,dc=org
        cn:alice: #dn: cn=alice,ou=people,c=global,dc=example,dc=org
          .#bindPassword: userPassword
          .#allowDN: dc=org # allow alice to request everything

          .#objectclass: posixAccount
          .@description: Main organization admin
          .<uid:homeDirectory:uidNumber:gidNumber: alice:/home/alice:1000:1000 #RFC(01): not yet implemented
          .@loginShell: /bin/bash
          .@userPassword: {{ hscVaultSecret '/secret/ldap/users/global/alice#password' | passwordType 'base64' }} #RFC(02): not yet implemented
        cn:bob: #dn: cn=bob,ou=people,c=global,dc=example,dc=org
          .#bindPassword: userPassword
          .#allowDN: ou=group,dc=example,dc=org # allow bob request only for user groups

          .#objectclass: posixAccount
          .<uid:homeDirectory:uidNumber:gidNumber: bob:/home/bob:1001:1001 #RFC(01): not yet implemented
          .@userPassword: {{ hscVaultSecret '/secret/ldap/users/global/bob#password' | passwordType 'base64' }} #RFC(02): not yet implemented

    c:fr: #dn: c=fr,dc=example,dc=org
      ou:people: #dn: ou=people,c=fr,dc=example,dc=org
        cn:charlie: #dn: cn=charlie,ou=people,c=fr,dc=example,dc=org
          .#bindPassword: userPassword
          .#allowDN: [ou=group,dc=example,dc=org, c=fr,dc=example,dc=org] # allow charlie request only for user groups & fr peoples ...
          .#denyDN: cn=admin,ou=group,dc=example,dc=org # ...but deny access to owner group

          .#objectclass: posixAccount
          .<uid:homeDirectory:uidNumber:gidNumber: charlie:/home/charlie:1100:1000 #RFC(01): not yet implemented
          .@userPassword: {{ hscVaultSecret '/secret/ldap/users/global/bob#password' | passwordType 'base64' }} #RFC(02): not yet implemented
        {{- range $id, $name := (hscVaultList 'secret/ldap/users/fr' | eval | without 'charlie') }} #RFC(02): not yet implemented
        cn:{{ $name }}:
          .#bindPassword: userPassword
          # NOTE: all user will not have the ability to make any search request (deny all policy by default)

          .#objectclass: posixAccount
          .<uid:homeDirectory:uidNumber:gidNumber: charlie:/home/{{ $name }}:{{ add $id 1101 }}:1001 #RFC(01): not yet implemented
          .@userPassword: {{ hscVaultSecret (printf '/secret/ldap/users/global/%s#password' $name) | passwordType 'base64' }} #RFC(02): not yet implemented
        {{- end }}

    c:uk: #dn: c=uk,dc=example,dc=org
      ou:people: #dn: ou=people,c=fr,dc=example,dc=org
        cn:eve: #dn: cn=eve,ou=people,c=uk,dc=example,dc=org
          #NOTE: eve can't make any LDAP request (not .#bindPassword property)
          .#objectclass: posixAccount
          .<uid:homeDirectory:uidNumber:gidNumber: eve:/home/eve:1003:1002 #RFC(01): not yet implemented
          .@userPassword: eve

.#schemas: #RFC(03): not yet implemented
  objectclasses:
  - posixGroup:1.3.6.1.1.1.2.2:structural:Abstraction of a group of accounts
  - posixAccount:1.3.6.1.1.1.2.0:auxiliary:Abstraction of an account with POSIX attributes
```

## RFCs
### One-line multiple attribute (12/06/2022)
In order to reduce the file size and to make some information mode readable, it could be useful to define several
attributes on the same line. For example, with the `posixAccount` object, defining some attributes using an equivalent
syntax that the `/etc/passwd` file could increase the readability (`alice:x:1000:1000::/home/alice:/usr/bin/bash`).

```bnf
<one_line_attrs> ::= ".<" <attrs> ":"
<attrs> ::= <attr> | <attr> ":" <attrs>
<attr> ::= <word>+ | "_"
```

> _NOTE: the `_` is used when we don't care of the attribute value_
> _NOTE²: BNF rules can be tested [here](https://bnfplayground.pauliankline.com/?bnf=%3Cone_line_attrs%3E%20%3A%3A%3D%20%22.%3C%22%20%3Cattrs%3E%20%22%3A%22%0A%3Cattrs%3E%20%3A%3A%3D%20%3Cattr%3E%20%7C%20%3Cattr%3E%20%22%3A%22%20%3Cattrs%3E%0A%3Cattr%3E%20%3A%3A%3D%20%3Cword%3E%2B%20%7C%20%22_%22%0A%0A%3Cword%3E%20%3A%3A%3D%20(%3Clower%3E%20%7C%20%3Cupper%3E%20%7C%20%3Cdigit%3E)%2B%0A%3Cupper%3E%20%3A%3A%3D%20%22A%22%20%7C%20%22B%22%20%7C%20%22C%22%20%7C%20%22D%22%20%7C%20%22E%22%20%7C%20%22F%22%20%7C%20%22G%22%20%7C%20%22H%22%20%7C%20%22I%22%20%7C%20%22J%22%20%7C%20%22K%22%20%7C%20%22L%22%20%7C%20%22M%22%20%7C%20%22N%22%20%7C%20%22O%22%20%7C%20%22P%22%20%7C%20%22Q%22%20%7C%20%22R%22%20%7C%20%22S%22%20%7C%20%22T%22%20%7C%20%22U%22%20%7C%20%22V%22%20%7C%20%22W%22%20%7C%20%22X%22%20%7C%20%22Y%22%20%7C%20%22Z%22%0A%3Clower%3E%20%3A%3A%3D%20%22a%22%20%7C%20%22b%22%20%7C%20%22c%22%20%7C%20%22d%22%20%7C%20%22e%22%20%7C%20%22f%22%20%7C%20%22g%22%20%7C%20%22h%22%20%7C%20%22i%22%20%7C%20%22j%22%20%7C%20%22k%22%20%7C%20%22l%22%20%7C%20%22m%22%20%7C%20%22n%22%20%7C%20%22o%22%20%7C%20%22p%22%20%7C%20%22q%22%20%7C%20%22r%22%20%7C%20%22s%22%20%7C%20%22t%22%20%7C%20%22u%22%20%7C%20%22v%22%20%7C%20%22w%22%20%7C%20%22x%22%20%7C%20%22y%22%20%7C%20%22z%22%0A%3Cdigit%3E%20%3A%3A%3D%20%221%22%20%7C%20%222%22%20%7C%20%223%22%20%7C%20%224%22%20%7C%20%225%22%20%7C%20%226%22%20%7C%20%227%22%20%7C%20%228%22%20%7C%20%229%22%20%7C%20%220%22%0A&name=One-line%20multiple%20attribute)_

#### Example
```yaml
.<uid:_:uidNumber:gidNumber:_:homeDirectory:loginShell: alice:x:1000:1000::/home/alice:/usr/bin/bash
```
will generate
 ```yaml
.@uid: alice
.@uidNumber: 1000
.@gidNumber: 1000
.@homeDirectory: /home/alice
.@loginShell: /usr/bin/alice
 ```

### Go-templates (at boot/at runtime) (12/06/2022)
Using `go-template` could be used to add some "smart" configurations and allows dynamic values like password. For example,
we can store the password on Vault and use them directly inside the LDAP; customizations are easy (just need to add new 
function) and as a security layer for sensitive information like password. It also adds the ability to update password
without restarting/generating the LDAP directory.

I suggest two mechanism:
- `go-templating` during runtime, inside LDAP attribute. Just before generating the attribute values, we can interpolate
  these dynamic values. To achieve this goal, we can make custom function to generate a go-template function that will
  be called during runtime execution.
- `go-templating` during the LDAP directory generation.

### Schema generation  (12/06/2022)
Some LDAP tools needs metadata like `objectclass` and `attributes` definition. We could generate them dynamically using
the `.#objectclass` property, the content of each object and some extra information like `.#schema`. _Need more details_