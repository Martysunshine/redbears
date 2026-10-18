<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/clipboard/open-clipboard.yml -->
rule:
  meta:
    name: open clipboard
    namespace: host-interaction/clipboard
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Collection::Clipboard Data [T1115]
    examples:
      - 6f99a2c8944cb02ff28c6f9ced59b161:0x403180
  features:
    - and:
      - api: user32.OpenClipboard
      - optional:
        - api: user32.CloseClipboard
