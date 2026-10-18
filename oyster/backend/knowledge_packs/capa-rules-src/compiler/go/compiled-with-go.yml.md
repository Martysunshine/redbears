<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/go/compiled-with-go.yml -->
rule:
  meta:
    name: compiled with Go
    namespace: compiler/go
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: file
      dynamic: file
    examples:
      - 49a34cfbeed733c24392c9217ef46bb6
  features:
    - or:
      - string: /^Go build ID:/
      - substring: "go.buildid"
      - string: /^Go buildinf:/
      - string: /\bgo1\.\d/
      - substring: "runtime.main"
      - substring: "main.main"
      - substring: "runtime.gcWork"
