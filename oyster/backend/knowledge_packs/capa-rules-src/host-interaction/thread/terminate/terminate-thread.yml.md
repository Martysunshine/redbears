<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/thread/terminate/terminate-thread.yml -->
rule:
  meta:
    name: terminate thread
    namespace: host-interaction/thread/terminate
    authors:
      - moritz.raabe@mandiant.com
      - michael.hunhoff@mandiant.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Process::Terminate Thread [C0039]
    examples:
      - Practical Malware Analysis Lab 03-02.dll_:0x10003286
      - B5F85C26D7AA5A1FB4AF5821B6B5AB9B:0x407E90
  features:
    - or:
      - api: kernel32.TerminateThread
      - api: PsTerminateSystemThread
      - api: System.Threading.Thread.Abort
      - api: pthread_terminate
