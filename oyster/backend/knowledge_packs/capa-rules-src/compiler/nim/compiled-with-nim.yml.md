<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/nim/compiled-with-nim.yml -->
rule:
  meta:
    name: compiled with Nim
    namespace: compiler/nim
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: file
      dynamic: file
    examples:
      - 580c37831fe98a254eb6c61c692c70d8.exe_
  features:
    - or:
      - substring: "NimMain"
      - substring: "NimMainModule"
      - substring: "NimMainInner"
      - substring: "io.nim"
      - substring: "fatal.nim"
      - substring: "system.nim"
      - substring: "alloc.nim"
      - substring: "osalloc.nim"
