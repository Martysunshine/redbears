<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/http/client/connect-to-http-server.yml -->
rule:
  meta:
    name: connect to HTTP server
    namespace: communication/http/client
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::HTTP Communication::Connect to Server [C0002.009]
    examples:
      - 6f99a2c8944cb02ff28c6f9ced59b161:0x40E2F0
  features:
    - and:
      - optional:
        - match: create HTTP request
      - api: wininet.InternetConnect
