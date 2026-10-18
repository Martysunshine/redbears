<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/create/create-process-on-linux.yml -->
rule:
  meta:
    name: create process on Linux
    namespace: host-interaction/process/create
    authors:
      - joakim@intezer.com
      - mehunhoff@google.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Process::Create Process [C0017]
    examples:
      - 7351f8a40c5450557b24622417fc478d:0x40236D
  features:
    - and:
      - or:
        - os: linux
        - os: android
      - or:
        - api: execve
        - and:
          - match: execute syscall
          - arch: aarch64
          - number: 0xdd = execve
        - api: execl
        - api: execlp
        - api: execle
        - api: execv
        - api: execvp
        - api: execvpe
        - api: posix_spawn
        - api: posix_spawnp
        - api: popen
        - api: fork
