<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/gui/set-application-hook.yml -->
rule:
  meta:
    name: set application hook
    namespace: host-interaction/gui
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: instruction
      dynamic: call
    examples:
      - Practical Malware Analysis Lab 12-03.exe_:0x401000
  features:
    - or:
      - api: user32.SetWindowsHookEx
      - api: user32.UnhookWindowsHookEx
