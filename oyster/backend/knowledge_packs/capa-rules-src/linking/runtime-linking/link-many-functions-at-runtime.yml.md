<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/linking/runtime-linking/link-many-functions-at-runtime.yml -->
rule:
  meta:
    name: link many functions at runtime
    namespace: linking/runtime-linking
    authors:
      - moritz.raabe@mandiant.com
      - joakim@intezer.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Execution::Shared Modules [T1129]
    examples:
      - b7b5e1253710d8927cbe07d52d2d2e10:0x401000
  features:
    - or:
      - count(match(link function at runtime on Windows)): 5 or more
      - count(match(link function at runtime on Linux)): 5 or more
