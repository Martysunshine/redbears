<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/thread/list/enumerate-threads.yml -->
rule:
  meta:
    name: enumerate threads
    namespace: host-interaction/thread/list
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::Process Discovery [T1057]
    mbc:
      - Process::Enumerate Threads [C0064]
    examples:
      - Practical Malware Analysis Lab 05-01.dll_:0x10006BD5
  features:
    - and:
      - api: kernel32.Thread32First
      - api: kernel32.Thread32Next
      - optional:
        - basic block:
          - and:
            - or:
              - number: 0x4 = TH32CS_SNAPTHREAD
              # TH32CS_SNAPTHREAD includes all threads in the system in the snapshot
            - api: kernel32.CreateToolhelp32Snapshot
        - call:
          - and:
            - or:
              - number: 0x4 = TH32CS_SNAPTHREAD
            - api: kernel32.CreateToolhelp32Snapshot
