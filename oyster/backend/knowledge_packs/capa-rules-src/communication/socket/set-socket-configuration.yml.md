<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/socket/set-socket-configuration.yml -->
rule:
  meta:
    name: set socket configuration
    namespace: communication/socket
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - Communication::Socket Communication::Set Socket Config [C0001.001]
    examples:
      - 6A352C3E55E8AE5ED39DC1BE7FB964B1:0x1000C1F0
  features:
    - or:
      - api: ws2_32.setsockopt
      - api: ws2_32.#21 = setsockopt
      - api: ws2_32.ioctlsocket
      - api: ws2_32.#10 = ioctlsocket
