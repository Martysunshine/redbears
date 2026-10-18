<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/file-managers/gather-cuteftp-information.yml -->
rule:
  meta:
    name: gather cuteftp information
    namespace: collection/file-managers
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Credential Access::Credentials from Password Stores [T1555]
    references:
      - https://en.wikipedia.org/wiki/CuteFTP
      - https://www.globalscape.com/cuteftp
    examples:
      - 5a2f620f29ca2f44fc22df67b674198f:0x40531A
  features:
    - and:
      - substring: "\\sm.dat"
      - or:
        - string: /\\GlobalSCAPE\\CuteFTP/i
        - string: /\\GlobalSCAPE\\CuteFTP Pro/i
        - substring: "\\CuteFTP"
