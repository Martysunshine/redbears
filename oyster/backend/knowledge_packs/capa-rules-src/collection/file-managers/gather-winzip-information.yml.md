<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/file-managers/gather-winzip-information.yml -->
rule:
  meta:
    name: gather winzip information
    namespace: collection/file-managers
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Credential Access::Credentials from Password Stores [T1555]
    references:
      - https://www.winzip.com/win/en/pages/old-brands/nico-mak-computing/index.html
    examples:
      - 5a2f620f29ca2f44fc22df67b674198f:0x40E237
  features:
    - or:
      - and:
        - substring: "Software\\Nico Mak Computing\\WinZip\\FTP"
        - substring: "Software\\Nico Mak Computing\\WinZip\\mru\\jobs"
      - and:
        - string: "Site"
        - string: "UserID"
        - string: "xflags"
        - string: "Port"
        - string: "Folder"
