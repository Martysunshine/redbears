<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/http/client/get-http-response-content-encoding.yml -->
rule:
  meta:
    name: get HTTP response content encoding
    namespace: communication/http/client
    authors:
      - matthew.williams@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Communication::HTTP Communication::Get Response [C0002.017]
    examples:
      - FBBAAF569B63F6398503E4F1979CABEF:0x4068D9
  features:
    - and:
      - api: wininet.HttpQueryInfo
      - number: 0x1D = HTTP_QUERY_CONTENT_ENCODING
