<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/ip/convert-ip-address-from-string.yml -->
# generated using capa explorer for IDA Pro
rule:
  meta:
    name: convert IP address from string
    namespace: communication/ip
    authors:
      - "@mr-tz"
    scopes:
      static: basic block
      dynamic: call
    examples:
      - 0796F1C1EA0A142FC1EB7109A44C86CB:0x405D20
  features:
    - and:
      - api: inet_pton
      - optional:
        - or:
          - number: 2 = AF_INET
          - number: 23 = AF_INET6
