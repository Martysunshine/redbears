<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/load-code/shellcode/execute-shellcode-via-createthreadpoolwait.yml -->
rule:
  meta:
    name: execute shellcode via CreateThreadpoolWait
    namespace: load-code/shellcode
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    references:
      - https://github.com/S4R1N/AlternativeShellcodeExec/blob/master/CreateThreadPoolWait/CreateThreadPoolWait.cpp
    examples:
      - a4f1f09a2b9bc87de90891da6c0fca28e2f88fd67034648060cef9862af9a3bf:0x10001010
  features:
    - and:
      - match: allocate or change RWX memory
      - api: CreateEvent
      - api: CreateThreadpoolWait
      - api: SetThreadpoolWait
      - or:
        - api: WaitForSingleObject
        - api: WaitForThreadpoolWaitCallbacks
