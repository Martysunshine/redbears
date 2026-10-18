<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/file-managers/gather-robo-ftp-information.yml -->
rule:
  meta:
    name: gather robo-ftp information
    namespace: collection/file-managers
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Credential Access::Credentials from Password Stores [T1555]
    references:
      - https://www.robo-ftp.com/
    examples:
      - 5a2f620f29ca2f44fc22df67b674198f:0x40D2CB
  features:
    - or:
      - and:
        - substring: "SOFTWARE\\Robo-FTP"
        - or:
          - substring: "\\FTPServers"
          - substring: "FTP File"
          - string: "FTP Count"
      - and:
        - string: "Password"
        - string: "ServerName"
        - string: "UserID"
        - string: "PortNumber"
        - string: "InitialDirectory"
        - string: "ServerType"
