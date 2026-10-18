<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/vb/compiled-from-visual-basic.yml -->
rule:
  meta:
    name: compiled from Visual Basic
    namespace: compiler/vb
    authors:
      - "@williballenthin"
    scopes:
      static: file
      dynamic: file
    examples:
      - 9bca6b99e7981208af4c7925b96fb9cf
  features:
    - and:
      - string: /VB5!.*/
      - import: msvbvm60.ThunRTMain
