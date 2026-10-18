<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/gui/window/hide/hide-graphical-window.yml -->
rule:
  meta:
    name: hide graphical window
    namespace: host-interaction/gui/window/hide
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    att&ck:
      - Defense Evasion::Hide Artifacts::Hidden Window [T1564.003]
    examples:
      - 39C05B15E9834AC93F206BC114D0A00C357C888DB567BA8F5345DA0529CBED41:0x10007250
  features:
    - and:
      - number: 0x0 = SW_HIDE
      - api: user32.ShowWindow
