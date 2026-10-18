<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/socket/udp/connect-udp-socket.yml -->
rule:
  meta:
    name: connect UDP socket
    namespace: communication/socket/udp
    authors:
      - mrhafizfarhad@gmail.com
    description: Detects UDP socket connections by combining UDP socket creation with connection attempts.
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::Socket Communication::UDP Client [C0001.013]
    examples:
      - 368239d36d221d8877a07ab6799e643a.elf_:0x20011E9
  features:
    - and:
      - match: create UDP socket
      - match: connect socket
