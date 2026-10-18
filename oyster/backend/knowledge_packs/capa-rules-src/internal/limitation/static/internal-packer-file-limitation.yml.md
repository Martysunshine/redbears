<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/internal/limitation/static/internal-packer-file-limitation.yml -->
rule:
  meta:
    name: (internal) packer file limitation
    namespace: internal/limitation/static
    authors:
      - william.ballenthin@mandiant.com
    description: |
      This sample appears to be packed.

      Packed samples have often been obfuscated to hide their logic.
      capa cannot handle obfuscation well using static analysis. This means the results may be misleading or incomplete.
      If possible, you should try to unpack this input file before analyzing it with capa.
      Alternatively, run the sample in a supported sandbox and invoke capa against the report to obtain dynamic analysis results.
    scopes:
      static: file
      dynamic: file
    examples:
      - CD2CBA9E6313E8DF2C1273593E649682
  features:
    - or:
      - match: anti-analysis/packer
