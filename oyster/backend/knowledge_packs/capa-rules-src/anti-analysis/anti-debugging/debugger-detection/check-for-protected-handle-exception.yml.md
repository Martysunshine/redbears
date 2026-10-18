<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-debugging/debugger-detection/check-for-protected-handle-exception.yml -->
rule:
  meta:
    name: check for protected handle exception
    namespace: anti-analysis/anti-debugging/debugger-detection
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection::SetHandleInformation [B0001.024]
    references:
      - https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/SetHandleInformation_API.cpp
    examples:
      - al-khaser_x86.exe_:0x430D20
  features:
    - and:
      - or:
        - description: SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
        - basic block:
          - and:
            - count(number(2)): 2 or more
            - api: SetHandleInformation
        - call:
          - and:
            - count(number(2)): 2 or more
            - api: SetHandleInformation
      - api: CloseHandle
