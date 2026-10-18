<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/http/client/create-http-request.yml -->
rule:
  meta:
    name: create HTTP request
    namespace: communication/http/client
    authors:
      - michael.hunhoff@mandiant.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::HTTP Communication::Create Request [C0002.012]
    examples:
      - 6f99a2c8944cb02ff28c6f9ced59b161:0x40E2F0
  features:
    - and:
      - or:
        - api: wininet.InternetOpen
        - api: System.Net.WebRequest::Create
        - api: System.Net.WebRequest::CreateDefault
        - api: System.Net.WebRequest::CreateHttp
      - optional:
        - api: wininet.InternetCloseHandle
