<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/socket/initialize-winsock-library.yml -->
rule:
  meta:
    name: initialize Winsock library
    namespace: communication/socket
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - Communication::Socket Communication::Initialize Winsock Library [C0001.009]
    examples:
      - 6A352C3E55E8AE5ED39DC1BE7FB964B1:0x10001D30
  features:
    - or:
      - api: ws2_32.WSAStartup
      - api: ws2_32.#115 = WSAStartup
