<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/terminate/terminate-process.yml -->
rule:
  meta:
    name: terminate process
    namespace: host-interaction/process/terminate
    authors:
      - moritz.raabe@mandiant.com
      - mehunhoff@google.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Process::Terminate Process [C0018]
    examples:
      - C91887D861D9BD4A5872249B641BC9F9:0x401A77
      - 9B7CCAA2AE6A5B96E3110EBCBC4311F6:0x10010307
  features:
    - or:
      - api: System.Diagnostics.Process::Kill
      - api: System.Diagnostics.Process::WaitForExit
      - api: System.Diagnostics.Process::WaitForExitAsync
      - api: System.Environment::Exit
      - api: System.Windows.Forms.Application::Exit
      - api: exit
      - api: Exit
      - api: RstrtMgr.RmShutdown
      - and:
        - os: linux
        - api: exit_group
      - and:
        - optional:
          - match: open process
        - or:
          - api: kernel32.TerminateProcess
          - api: ntdll.NtTerminateProcess
          - api: kernel32.ExitProcess
          - api: ZwTerminateProcess
