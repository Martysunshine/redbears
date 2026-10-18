<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/write/write-file-on-windows.yml -->
rule:
  meta:
    name: write file on Windows
    namespace: host-interaction/file-system/write
    authors:
      - william.ballenthin@mandiant.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - File System::Writes File [C0052]
    examples:
      - Practical Malware Analysis Lab 01-04.exe_:0x4011FC
      # ntdll
      - 563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299:0x1400025C4
  features:
    - or:
      - and:
        - os: windows
        - optional:
          - basic block:
            - or:
              - number: 0x40000000 = GENERIC_WRITE
              - number: 0x2 = FILE_WRITE_DATA
              - match: create or open file
          - call:
            - or:
              - number: 0x40000000 = GENERIC_WRITE
              - number: 0x2 = FILE_WRITE_DATA
              - match: create or open file
        - or:
          - api: kernel32.WriteFile
          - api: kernel32.WriteFileEx
          - api: NtWriteFile
          - api: ZwWriteFile
          - api: _fwrite
          - api: fwrite
