<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/executable/subfile/pe/contain-an-embedded-pe-file.yml -->
rule:
  meta:
    name: contain an embedded PE file
    namespace: executable/subfile/pe
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: file
      dynamic: file
    mbc:
      - Execution::Install Additional Program [B0023]
    examples:
      - Practical Malware Analysis Lab 01-04.exe_:0x4060
  features:
    - or:
      - count(characteristic(embedded pe)): 1 or more
      - count(string(This program cannot be run in DOS mode.)): 2 or more
