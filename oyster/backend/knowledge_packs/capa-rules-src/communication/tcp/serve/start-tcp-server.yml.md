<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/tcp/serve/start-tcp-server.yml -->
rule:
  meta:
    name: start TCP server
    namespace: communication/tcp/serve
    authors:
      - william.ballenthin@mandiant.com
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::Socket Communication::Start TCP Server [C0001.005]
    examples:
      - AF2F4142463F42548B8650A3ADF5CEB2:0x10010880
  features:
    - or:
      - and:
        - match: create TCP socket
        - api: listen
        - or:
          - api: accept
          - api: WSAAccept
      - api: System.Net.Sockets.TcpListener::Start
      - api: System.Net.Sockets.TcpListener::AcceptTcpClient
      - api: System.Net.Sockets.TcpListener::BeginAcceptTcpClient
      - api: System.Net.Sockets.TcpListener::AcceptTcpClientAsync
      - api: System.Net.Sockets.TcpListener::AcceptSocket
      - api: System.Net.Sockets.TcpListener::BeginAcceptSocket
      - api: System.Net.Sockets.TcpListener::AcceptSocketAsync
