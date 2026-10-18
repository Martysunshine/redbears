<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/hardware/mouse/swap-mouse-buttons.yml -->
rule:
  meta:
    name: swap mouse buttons
    namespace: host-interaction/hardware/mouse
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - Impact::Modify Hardware::Mouse [B0042.002]
    examples:
      - B7841B9D5DC1F511A93CC7576672EC0C:0x10007250
  features:
    - or:
      - api: user32.SwapMouseButton
