<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-debugging/debugger-detection/check-processdebugport.yml -->
rule:
  meta:
    name: check ProcessDebugPort
    namespace: anti-analysis/anti-debugging/debugger-detection
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection::NtQueryInformationProcess [B0001.012]
    references:
      - https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/NtQueryInformationProcess_ProcessDebugPort.cpp
    examples:
      - kernel32.dll_:0x7DD97899
  features:
    - and:
      - api: NtQueryInformationProcess
      - number: 0x7 = ProcessDebugPort
