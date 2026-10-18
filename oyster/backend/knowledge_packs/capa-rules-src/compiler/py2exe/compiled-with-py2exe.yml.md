<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/py2exe/compiled-with-py2exe.yml -->
rule:
  meta:
    name: compiled with py2exe
    namespace: compiler/py2exe
    authors:
      - "@_re_fox"
    scopes:
      static: basic block
      dynamic: call
    examples:
      - ed888dc2f04f5eac83d6d14088d002de:0x40194A
  features:
    - and:
      - string: "PY2EXE_VERBOSE"
      - api: getenv
