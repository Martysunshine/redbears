<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/thread/suspend/suspend-thread.yml -->
rule:
  meta:
    name: suspend thread
    namespace: host-interaction/thread/suspend
    authors:
      - 0x534a@mailbox.org
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Process::Suspend Thread [C0055]
    examples:
      - 787cbc8a6d1bc58ea169e51e1ad029a637f22560660cc129ab8a099a745bd50e:0x502f4c
  features:
    - or:
      - api: kernel32.SuspendThread
      - api: ntdll.NtSuspendThread
      - api: ntdll.ZwSuspendThread
      - api: System.Threading.Thread::Suspend
      - api: System.Threading.Thread::Sleep
