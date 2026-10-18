<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/internal/limitation/static/internal-visual-basic-file-limitation.yml -->
rule:
  meta:
    name: (internal) Visual Basic file limitation
    namespace: internal/limitation/static
    authors:
      - "@mr-tz"
    description: |
      This sample appears to be compiled from Visual Basic.

      Visual Basic is a Microsoft programming language that can be compiled to native code or an intermediate
      representation called P-Code.
      capa cannot handle Visual Basic executables well. This means that the results will be misleading or incomplete.
      You may have to analyze the file manually, for example using a tool like VB Decompiler.
    scopes:
      static: file
      dynamic: file
    examples:
      - 9bca6b99e7981208af4c7925b96fb9cf
  features:
    - or:
      - match: compiler/vb
