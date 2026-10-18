<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/d/compiled-with-dmd.yml -->
rule:
  meta:
    name: compiled with dmd
    namespace: compiler/d
    authors:
      - "@_re_fox"
    scopes:
      static: file
      dynamic: file
    references:
      - https://github.com/dlang/dmd
    examples:
      - 321338196a46b600ea330fc5d98d0699
  features:
    - and:
      - section: ._deh
      - section: .tp
      - section: .dp
      - section: .minfo
