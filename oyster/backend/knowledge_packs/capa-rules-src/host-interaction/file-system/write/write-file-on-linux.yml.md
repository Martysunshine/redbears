<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/write/write-file-on-linux.yml -->
rule:
  meta:
    name: write file on Linux
    namespace: host-interaction/file-system/write
    authors:
      - joakim@intezer.com
      - mehunhoff@google.com
    scopes:
      static: instruction
      dynamic: call
    mbc:
      - File System::Writes File [C0052]
    examples:
      - 7351f8a40c5450557b24622417fc478d:0x401E14
  features:
    - and:
      - or:
        - os: linux
        - os: android
      - or:
        - api: fputc
        - api: fputs
        - api: putc
        - api: write
        - api: fputwc
        - api: putwc
        - api: fputws
        - api: fwrite
        - api: putwchar
        - api: dprintf
        - api: vdprintf
        - api: fprintf
        - api: vfprintf
