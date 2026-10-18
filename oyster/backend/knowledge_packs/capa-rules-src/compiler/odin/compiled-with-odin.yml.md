<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/odin/compiled-with-odin.yml -->
rule:
  meta:
    name: compiled with Odin
    namespace: compiler/odin
    authors:
      - corkami@google.com
    scopes:
      static: file
      dynamic: file
    examples:
      - e17e6a79ed614f5468d0eed758629697
  features:
    - and:
      - substring: ".odin"
      - 2 or more:
        - string: "all_or_none"
        - string: "runtime"
        - substring: "soa_"
        - substring: "base/"
        - substring: "core/"
        - substring: "arena"
