<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/http/server/send-http-response.yml -->
rule:
  meta:
    name: send HTTP response
    namespace: communication/http/server
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - Communication::HTTP Communication::Send Response [C0002.016]
    examples:
      - 6A352C3E55E8AE5ED39DC1BE7FB964B1:0x10001B20
  features:
    - or:
      - api: httpapi.HttpSendHttpResponse
      - api: httpapi.HttpSendResponseEntityBody
