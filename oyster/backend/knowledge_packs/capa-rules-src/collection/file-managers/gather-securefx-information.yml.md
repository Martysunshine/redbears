<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/file-managers/gather-securefx-information.yml -->
rule:
  meta:
    name: gather securefx information
    namespace: collection/file-managers
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Credential Access::Credentials from Password Stores [T1555]
    references:
      - https://www.vandyke.com/products/securefx/index.html
    examples:
      - 5a2f620f29ca2f44fc22df67b674198f:0x4069DB
  features:
    - and:
      - substring: "\\Sessions"
      - string: ".ini"
      - substring: "Config Path"
      - or:
        - substring: "_VanDyke\\Config\\Sessions"
        - substring: "Software\\VanDyke\\SecureFX"
