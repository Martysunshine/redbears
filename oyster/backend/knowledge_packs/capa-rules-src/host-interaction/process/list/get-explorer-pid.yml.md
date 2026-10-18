<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/list/get-explorer-pid.yml -->
rule:
  meta:
    name: get Explorer PID
    namespace: host-interaction/process/list
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: basic block
      dynamic: span of calls
    att&ck:
      - Discovery::Process Discovery [T1057]
    references:
      - https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/ParentProcess.cpp
    examples:
      - al-khaser_x86.exe_:0x425210
  features:
    - and:
      - api: GetShellWindow
      - api: GetWindowThreadProcessId
