<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/http/get-http-content-length.yml -->
rule:
  meta:
    name: get HTTP content length
    namespace: communication/http
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Communication::HTTP Communication [C0002]
    examples:
      - 0596c4ea5aa8def47f22c85d75aaca95:0x1079C70
  features:
    - and:
      - api: wininet.HttpQueryInfo
      - number: 0x20000005 = HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_CONTENT_LENGTH
