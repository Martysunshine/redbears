<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-debugging/debugger-detection/check-process-job-object.yml -->
rule:
  meta:
    name: check process job object
    namespace: anti-analysis/anti-debugging/debugger-detection
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection [B0001]
    references:
      - https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/ProcessJob.cpp
    examples:
      - al-khaser_x86.exe_:0x426730
  features:
    - or:
      # static
      - and:
        - match: contain loop
        - basic block:
          - and:
            - api: kernel32.QueryInformationJobObject
            - number: 0x3 = JobObjectBasicProcessIdList
        - basic block:
          - and:
            - api: kernel32.OpenProcess
            - number: 0x400 = PROCESS_QUERY_INFORMATION
      # dynamic
      - and:
        - call:
          - and:
            - api: kernel32.QueryInformationJobObject
            - number: 0x3 = JobObjectBasicProcessIdList
        - call:
          - and:
            - api: kernel32.OpenProcess
            - number: 0x400 = PROCESS_QUERY_INFORMATION
