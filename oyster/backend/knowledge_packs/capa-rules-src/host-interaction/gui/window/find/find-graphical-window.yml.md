<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/gui/window/find/find-graphical-window.yml -->
rule:
  meta:
    name: find graphical window
    namespace: host-interaction/gui/window/find
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: instruction
      dynamic: call
    att&ck:
      - Discovery::Application Window Discovery [T1010]
    examples:
      - 7C843E75D4F02087B932FE280DF9C90C:0x41B180
  features:
    - or:
      - api: user32.FindWindow
      - api: user32.FindWindowEx
