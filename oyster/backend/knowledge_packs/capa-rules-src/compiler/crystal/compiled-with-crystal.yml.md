<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/crystal/compiled-with-crystal.yml -->
rule:
  meta:
    name: compiled with Crystal
    namespace: compiler/crystal
    authors:
      - corkami@google.com
    scopes:
      static: file
      dynamic: file
    examples:
      - 29a76e413ffe0f78b62926b8455082d6
  features:
    - 2 or more:
      - string: "CRYSTAL_LOAD_DEBUG_INFO"
      - string: "CRYSTAL_PATH"
      - string: "CRYSTAL_VERSION"
      - string: "CRYSTAL_CALLSTACK_FULL_INFO"
      - substring: "__crystal_raise"
      - substring: "Unhandled exception in spawn"
      - substring: "Crystal::"
