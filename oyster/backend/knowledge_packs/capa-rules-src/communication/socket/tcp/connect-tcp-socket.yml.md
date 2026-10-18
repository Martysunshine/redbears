<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/socket/tcp/connect-tcp-socket.yml -->
rule:
  meta:
    name: connect TCP socket
    namespace: communication/socket/tcp
    authors:
      - moritz.raabe@mandiant.com
      - joakim@intezer.com
      - mrhafizfarhad@gmail.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::Socket Communication::Connect Socket [C0001.004]
    examples:
      - Practical Malware Analysis Lab 01-01.dll_:0x10001010
  features:
    - and:
      - match: create TCP socket
      - match: connect socket
