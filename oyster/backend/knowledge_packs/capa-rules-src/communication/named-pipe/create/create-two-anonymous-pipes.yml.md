<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/named-pipe/create/create-two-anonymous-pipes.yml -->
rule:
  meta:
    name: create two anonymous pipes
    namespace: communication/named-pipe/create
    authors:
      - matthew.williams@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::Interprocess Communication::Create Pipe [C0003.001]
    examples:
      - Practical Malware Analysis Lab 14-02.exe_:0x4011C0
  features:
    - and:
      - count(api(CreatePipe)): 2
