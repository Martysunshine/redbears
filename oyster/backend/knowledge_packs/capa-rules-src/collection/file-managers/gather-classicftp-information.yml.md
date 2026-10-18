<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/file-managers/gather-classicftp-information.yml -->
rule:
  meta:
    name: gather classicftp information
    namespace: collection/file-managers
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Credential Access::Credentials from Password Stores [T1555]
    references:
      - https://www.nchsoftware.com/classic/index.html
    examples:
      - 5a2f620f29ca2f44fc22df67b674198f:0x40735E
  features:
    - or:
      - substring: "Software\\NCH Software\\ClassicFTP\\FTPAccounts"
