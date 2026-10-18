<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/file-managers/gather-cyberduck-information.yml -->
rule:
  meta:
    name: gather cyberduck information
    namespace: collection/file-managers
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Credential Access::Credentials from Password Stores [T1555]
    references:
      - https://cyberduck.io/ftp/
    examples:
      - 5a2f620f29ca2f44fc22df67b674198f:0x40D965
  features:
    - and:
      - substring: "\\Cyberduck"
      - or:
        - string: "user.config"
        - string: ".duck"
