<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/c2/shell/create-reverse-shell.yml -->
rule:
  meta:
    name: create reverse shell
    namespace: communication/c2/shell
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Execution::Command and Scripting Interpreter::Windows Command Shell [T1059.003]
    mbc:
      - Impact::Remote Access::Reverse Shell [B0022.001]
    examples:
      - C91887D861D9BD4A5872249B641BC9F9:0x401A77
  features:
    - or:
      - and:
        - match: create pipe
        - api: kernel32.PeekNamedPipe
        - api: kernel32.CreateProcess
        - api: kernel32.ReadFile
        - api: kernel32.WriteFile
      - and:
        - match: host-interaction/process/create
        - match: read pipe
        - match: write pipe
      - and:
        - match: create pipe
        - match: host-interaction/process/create
        - or:
          - basic block:
            - and:
              - count(api(SetHandleInformation)): 2 or more
              - number: 1 = HANDLE_FLAG_INHERIT
          - call:
            - and:
              - count(api(SetHandleInformation)): 2 or more
              - number: 1 = HANDLE_FLAG_INHERIT
