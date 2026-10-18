<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/file-managers/gather-ffftp-information.yml -->
rule:
  meta:
    name: gather ffftp information
    namespace: collection/file-managers
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Credential Access::Credentials from Password Stores [T1555]
    references:
      - http://www2.biglobe.ne.jp/sota/ffftp-e.html
    examples:
      - 5a2f620f29ca2f44fc22df67b674198f:0x40614B
  features:
    - or:
      - and:
        - or:
          - substring: "Software\\Sota\\FFFTP\\Options"
          - substring: "Software\\Sota\\FFFTP"
        - or:
          - substring: "CredentialSalt"
          - substring: "CredentialCheck"
      - and:
        - string: "Password"
        - string: "UserName"
        - string: "HostAdrs"
        - string: "RemoteDir"
        - string: "Port"
