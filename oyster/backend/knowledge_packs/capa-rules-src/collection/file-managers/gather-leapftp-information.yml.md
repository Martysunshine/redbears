<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/file-managers/gather-leapftp-information.yml -->
rule:
  meta:
    name: gather leapftp information
    namespace: collection/file-managers
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Credential Access::Credentials from Password Stores [T1555]
    examples:
      - 5a2f620f29ca2f44fc22df67b674198f:0x407A33
  features:
    - or:
      - and:
        - string: "InstallPath"
        - string: "DataDir"
        - string: "sites.dat"
        - string: "sites.ini"
      - and:
        - or:
          - substring: "SOFTWARE\\LeapWare"
          - substring: "\\LeapWare\\LeapFTP"
        - 2 or more:
          - string: "sites.dat"
          - string: "sites.ini"
          - string: "leapftp"
