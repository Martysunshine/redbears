<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/file-managers/gather-coreftp-information.yml -->
rule:
  meta:
    name: gather coreftp information
    namespace: collection/file-managers
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Credential Access::Credentials from Password Stores [T1555]
    references:
      - http://www.coreftp.com/
    examples:
      - 5a2f620f29ca2f44fc22df67b674198f:0x4063FD
  features:
    - or:
      - substring: "Software\\FTPWare\\COREFTP\\Sites"
      - and:
        - string: "Host"
        - string: "User"
        - string: "Port"
        - string: "PthR"
