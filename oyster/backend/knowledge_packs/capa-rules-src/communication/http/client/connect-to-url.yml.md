<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/http/client/connect-to-url.yml -->
rule:
  meta:
    name: connect to URL
    namespace: communication/http/client
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: instruction
      dynamic: call
    mbc:
      - Communication::HTTP Communication::Open URL [C0002.004]
    examples:
      - 6f99a2c8944cb02ff28c6f9ced59b161:0x40E2F0
  features:
    - and:
      - api: wininet.InternetOpenUrl
