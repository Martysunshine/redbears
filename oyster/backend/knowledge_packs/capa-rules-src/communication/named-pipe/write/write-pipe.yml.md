<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/named-pipe/write/write-pipe.yml -->
rule:
  meta:
    name: write pipe
    namespace: communication/named-pipe/write
    authors:
      - moritz.raabe@mandiant.com
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::Interprocess Communication::Write Pipe [C0003.004]
    examples:
      - C91887D861D9BD4A5872249B641BC9F9:0x401A77
  features:
    - or:
      - and:
        - or:
          - match: create pipe
          - match: connect pipe
        - api: kernel32.WriteFile
      - api: kernel32.TransactNamedPipe
        description: writes and reads pipe in single operation
      - api: kernel32.CallNamedPipe
        description: connects, writes, and reads pipe in single operation
