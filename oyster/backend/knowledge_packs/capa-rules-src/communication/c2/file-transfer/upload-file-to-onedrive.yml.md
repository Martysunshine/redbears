<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/c2/file-transfer/upload-file-to-onedrive.yml -->
rule:
  meta:
    name: upload file to OneDrive
    namespace: communication/c2/file-transfer
    authors:
      - jaredswilson@google.com
      - ervinocampo@google.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Exfiltration::Exfiltration Over Web Service::Exfiltration to Cloud Storage [T1567.002]
    references:
      - https://cloud.google.com/blog/topics/threat-intelligence/apt41-arisen-from-dust
      - https://learn.microsoft.com/en-us/onedrive/developer/rest-api/concepts/upload?view=odsp-graph-online
    examples:
      - c40db0438a906eb0bec55093f1a0f2cc4cdc38104af0b4b4b3f18200a635c443
  features:
    - and:
      - substring: "graph.microsoft.com"
      - or:
        - substring: "/createUploadSession"
        - substring: "/content"
        - or:
          - substring: "/:children"
          - substring: "/children"
      - or:
        - substring: "/drive/items/"
        - substring: "/drive/root"
