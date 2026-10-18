<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/send-data.yml -->
rule:
  meta:
    name: send data
    namespace: communication
    authors:
      - william.ballenthin@mandiant.com
      - joakim@intezer.com
    description: all known techniques for sending data to a potential C2 server
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Command and Control::C2 Communication::Send Data [B0030.001]
    examples:
      - BFB9B5391A13D0AFD787E87AB90F14F5:0x13145D60
  features:
    - or:
      - and:
        - os: windows
        - or:
          - match: send HTTP request
          - match: send data on socket
          - match: send file via HTTP
          - match: send data to Internet
      - and:
        - os: linux
        - or: # Require network bound socket.
          - match: create TCP socket
          - match: create UDP socket
        - or:
          - match: send HTTP request
          - match: send data on socket
          - match: send file via HTTP
