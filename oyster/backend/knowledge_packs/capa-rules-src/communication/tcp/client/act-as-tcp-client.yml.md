<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/tcp/client/act-as-tcp-client.yml -->
rule:
  meta:
    name: act as TCP client
    namespace: communication/tcp/client
    authors:
      - william.ballenthin@mandiant.com
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::Socket Communication::TCP Client [C0001.008]
    examples:
      - Practical Malware Analysis Lab 01-01.dll_:0x10001010
  features:
    - or:
      - match: connect TCP socket
      - api: System.Net.Sockets.TcpClient::ctor
