<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/socket/get-socket-status.yml -->
rule:
  meta:
    name: get socket status
    namespace: communication/socket
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Discovery::System Network Configuration Discovery [T1016]
    mbc:
      - Communication::Socket Communication::Get Socket Status [C0001.012]
    examples:
      - 6A352C3E55E8AE5ED39DC1BE7FB964B1:0x1000C1F0
  features:
    - or:
      - api: ws2_32.select
      - api: ws2_32.#18 = select
