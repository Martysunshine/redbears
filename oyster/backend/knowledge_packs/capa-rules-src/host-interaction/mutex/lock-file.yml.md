<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/mutex/lock-file.yml -->
rule:
  meta:
    name: lock file
    namespace: host-interaction/mutex
    authors:
      - joakim@intezer.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Process::Create Mutex [C0042]
    examples:
      - 7351f8a40c5450557b24622417fc478d:0x40858F
  features:
    - and:
      - or:
        - os: linux
        - os: android
      - api: fcntl
      - number: 1 = F_WRLCK
      - number: 6 = F_SETLK
