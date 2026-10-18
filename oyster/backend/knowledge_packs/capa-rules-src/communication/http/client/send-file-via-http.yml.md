<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/http/client/send-file-via-http.yml -->
rule:
  meta:
    name: send file via HTTP
    namespace: communication/http/client
    authors:
      - matthew.williams@mandiant.com
    scopes:
      static: instruction
      dynamic: call
    mbc:
      - Communication::HTTP Communication::Send Data [C0002.005]
    examples:
      - 3d760b6fc84571c928bed835863fc302:0x403687
  features:
    - and:
      - api: wininet.InternetWriteFile
