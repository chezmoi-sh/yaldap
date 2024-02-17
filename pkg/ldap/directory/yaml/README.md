# LDAP directory implementation for YAML format

## Why using YAML?

Nowadays, I found that `YAML` is overused to configure things that sometimes requires more simple markup languages (`ini`, `txt`, ...), or mode specific DSL (like `hcl`). Of course, `YAML` is now a well known markup language and can be easily use by almost everyone.
However, I personally chose `YAML` because it gives me a better representation of the directory structure;
I picture an LDAP directory as a file directory, with folders (`containers`) and files (`leafs`). The fact that `YAML` uses indentation to define the depth of a field reminds me the `tree` command and helps me a lot in the global representation of the LDAP directory.

## Syntax

As explained above, I chose the `YAML` format because it allows the LDAP directory to be represented like this:

```yaml
dc:org: #dn: dc=org
└── dc:example: #dn: dc=example,dc=org
    ├── ou:group: #dn: ou=group,dc=example,dc=org
    │   ├── cn:owner: #dn: cn=admin,ou=group,dc=example,dc=org
    │   ├── cn:dev: #dn: cn=dev,ou=group,dc=example,dc=org
    │   ├── cn:qa: #dn: cn=qa,ou=group,dc=example,dc=org
    │   └── cn:ok: #dn: cn=ok,ou=group,dc=example,dc=org
    ├── c:global: #dn: c=global,dc=example,dc=org
    │   └── ou:people: #dn: ou=people,c=global,dc=example,dc=org
    │       ├── cn:alice: #dn: cn=alice,ou=people,c=global,dc=example,dc=org
    │       └── cn:bob: #dn: cn=bob,ou=people,c=global,dc=example,dc=org
    ├── c:fr: #dn: c=fr,dc=example,dc=org
    │   └── ou:people: #dn: ou=people,c=fr,dc=example,dc=org
    │       └── cn:charlie: #dn: cn=charlie,ou=people,c=fr,dc=example,dc=org
    └── c:uk: #dn: c=uk,dc=example,dc=org
        └── ou:people: #dn: ou=people,c=fr,dc=example,dc=org
            └── cn:eve: #dn: cn=eve,ou=people,c=uk,dc=exa
```

### Rules of the syntax

- A `LDAP` object is represented by a `YAML` mapping node
  - All child `LDAP` objects are represented by `YAML` mappings nodes inside the parent `YAML` mapping node
- A `LDAP` attribute is represented by a `YAML` sequence or scalar node
  - All `YAML` scalar nodes will be converted into string
  - `YAML` sequence nodes can only contain scalar or sequential nodes
  - All `null` node will be ignored
- Any `YAML` extension to add specific behavior will be done using `YAML` tags
  - `!!ldap/bind:password` on an attribute will use this attribute as `bind` password
    - **Only one password can be set per object**
  - `!!ldap/acl:allow-on` allows the current object to search object inside the given DN
    - Can be a scalar (one) or a sequence (several) node
    - **These values are not stored inside the attribute**
  - `!!ldap/acl:deny-on` denies the current object to search object inside the given DN
    - Can be a scalar (one) or a sequence (several) node
    - **These values are not stored inside the attribute**

> [!NOTE]
> The `!!ldap/bind:password` handle hashed password during the `bind` operation.  
> Currently, only `argon2`, `bcrypt`, `pbkdf2` and `scrypt` are supported. See [README.md](../../../../README.md) for more details.

### Extension: `go` template

To extend the `YAML` syntax _(injecting secrets for example)_, the `YAML` parser will use the `text/template` package to parse the `YAML` file.
The format is the same as all other Go template (see [text/template](https://pkg.go.dev/text/template)) and uses `sprig` to add functions _(see http://masterminds.github.io/sprig/ for the list)_.  
Beside that, the `YAML` parser will add some functions to help the parsing:

- `readFile`: reads a file and return its content as a string (see [readFile](https://pkg.go.dev/io/ioutil#ReadFile))

### Example

```yaml
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
        userPassword: !!ldap/bind:password '{{ index (readFile "/run/secrets/passwords.json" | fromJson) alice }}'
        usermail: alice@example.org

      cn:bob: #dn: cn=bob,ou=people,c=global,dc=example,dc=org
        objectClass: posixAccount
        .#acl:
          - !!ldap/acl:allow-on ou=group,dc=example,dc=org # allow bob request only for user groups

        uid: bob
        homeDirectory: /home/bob
        uidNumber: 1001
        gidNumber: 1001
        userPassword: !!ldap/bind:password '{{ index (readFile "/run/secrets/passwords.json" | fromJson) bob }}'

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
        userPassword: !!ldap/bind:password '{{ index (readFile "/run/secrets/passwords.json" | fromJson) charlie }}'

  c:uk: #dn: c=uk,dc=example,dc=org
    ou:people: #dn: ou=people,c=fr,dc=example,dc=org
      cn:eve: #dn: cn=eve,ou=people,c=uk,dc=example,dc=org
        objectClass: posixAccount
        #NOTE: eve can't make any LDAP request (no !!ldap/bind:password field)
        uid: eve
        homeDirectory: /home/eve
        uidNumber: 1003
        gidNumber: 1002
        userPassword: '{{ index (readFile "/run/secrets/passwords.json" | fromJson) eve }}'
```

## RFCs

### Schema generation (12/06/2022)

Some LDAP tools needs metadata like `objectclass` and `attributes` definition. _Need more details_
