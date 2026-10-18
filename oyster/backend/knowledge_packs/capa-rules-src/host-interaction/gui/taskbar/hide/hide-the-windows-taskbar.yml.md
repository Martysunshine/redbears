<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/gui/taskbar/hide/hide-the-windows-taskbar.yml -->
rule:
  meta:
    name: hide the Windows taskbar
    namespace: host-interaction/gui/taskbar/hide
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Hide Artifacts [T1564]
    examples:
      - 39C05B15E9834AC93F206BC114D0A00C357C888DB567BA8F5345DA0529CBED41:0x10007250
  features:
    - and:
      - match: find taskbar
      - match: hide graphical window
