<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/gui/console/set-console-window-title.yml -->
rule:
  meta:
    name: set console window title
    namespace: host-interaction/gui/console
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - Operating System::Console [C0033]
    examples:
      - mimikatz.exe_:0x44570F
  features:
    - or:
      - api: kernel32.SetConsoleTitle
