<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/inject/free-user-process-memory.yml -->
rule:
  meta:
    name: free user process memory
    namespace: host-interaction/process/inject
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Process Injection [T1055]
    mbc:
      - Memory::Free Memory [C0044]
    examples:
      - 493167E85E45363D09495D0841C30648:0x404CA0
  features:
    - and:
      - match: attach user process memory
      - number: 0xFFFFFFFF = NtCurrentProcess()
      - api: ZwFreeVirtualMemory
      - optional:
        - match: find process by PID
