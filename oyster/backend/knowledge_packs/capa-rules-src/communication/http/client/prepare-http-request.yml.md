<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/http/client/prepare-http-request.yml -->
rule:
  meta:
    name: prepare HTTP request
    namespace: communication/http/client
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - Communication::HTTP Communication::Create Request [C0002.012]
    examples:
      - 6A352C3E55E8AE5ED39DC1BE7FB964B1:0x10002650
  features:
    - or:
      - api: winhttp.WinHttpOpenRequest
