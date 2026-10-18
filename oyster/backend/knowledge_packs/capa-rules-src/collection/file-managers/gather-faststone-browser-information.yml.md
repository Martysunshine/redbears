<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/file-managers/gather-faststone-browser-information.yml -->
rule:
  meta:
    name: gather faststone-browser information
    namespace: collection/file-managers
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Credential Access::Credentials from Password Stores [T1555]
    references:
      - https://www.faststone.org/
    examples:
      - 5a2f620f29ca2f44fc22df67b674198f:0x40E04F
  features:
    - and:
      - substring: "FastStone Browser"
      - string: "FTPList.db"
