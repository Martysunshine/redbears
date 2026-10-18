<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/gui/taskbar/find/find-taskbar.yml -->
rule:
  meta:
    name: find taskbar
    namespace: host-interaction/gui/taskbar/find
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Discovery::Taskbar Discovery [B0043]
    examples:
      - B7841B9D5DC1F511A93CC7576672EC0C:0x10007250
  features:
    - and:
      - string: "Shell_TrayWnd"
      - match: find graphical window
