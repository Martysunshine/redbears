<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/inject/allocate-user-process-rwx-memory.yml -->
rule:
  meta:
    name: allocate user process RWX memory
    namespace: host-interaction/process/inject
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Process Injection [T1055]
    examples:
      - 493167E85E45363D09495D0841C30648:0x404B00
  features:
    - and:
      - match: attach user process memory
      - match: allocate or change RWX memory
      - number: 0xFFFFFFFF = NtCurrentProcess()
      - optional:
        - match: find process by PID
