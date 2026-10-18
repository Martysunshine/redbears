<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/c2/file-transfer/write-and-execute-a-file.yml -->
rule:
  meta:
    name: write and execute a file
    namespace: communication/c2/file-transfer
    maec/malware-category: launcher
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Execution::Install Additional Program [B0023]
    examples:
      - 9324D1A8AE37A36AE560C37448C9705A:0x403A40
      - Practical Malware Analysis Lab 01-04.exe_:0x4011FC
  features:
    - and:
      - match: host-interaction/file-system/write
      - match: host-interaction/process/create
