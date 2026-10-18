<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/http/client/receive-http-response.yml -->
rule:
  meta:
    name: receive HTTP response
    namespace: communication/http/client
    authors:
      - mehunhoff@google.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::HTTP Communication::Get Response [C0002.017]
    examples:
      - 6A352C3E55E8AE5ED39DC1BE7FB964B1:0x10002790
  features:
    - or:
      - api: winhttp.WinHttpReceiveResponse
      - and:
        - api: winhttp.WinHttpReadData
        - optional:
          - api: winhttp.WinHttpQueryDataAvailable
      - and:
        - format: dotnet
        - or:
          - api: System.Net.WebRequest::GetResponse
          - class: System.Net.Http.HttpResponseMessage
