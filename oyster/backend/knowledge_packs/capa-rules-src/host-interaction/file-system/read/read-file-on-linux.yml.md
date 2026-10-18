<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/read/read-file-on-linux.yml -->
rule:
  meta:
    name: read file on Linux
    namespace: host-interaction/file-system/read
    authors:
      - joakim@intezer.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - File System::Read File [C0051]
    examples:
      - 7351f8a40c5450557b24622417fc478d:0x4059AD
  features:
    - and:
      - or:
        - os: linux
        - os: android
      - optional:
        - match: create or open file
      - or:
        - api: fgetc
        - api: fgets
        - api: getc
        - api: getchar
        - api: read
        - api: getline
        - api: getdelim
        - api: fgetwc
        - api: getwc
        - api: fscanf
        - api: vfscanf
        - api: fread
