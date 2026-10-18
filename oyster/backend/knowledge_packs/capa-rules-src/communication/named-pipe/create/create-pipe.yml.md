<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/named-pipe/create/create-pipe.yml -->
rule:
  meta:
    name: create pipe
    namespace: communication/named-pipe/create
    authors:
      - moritz.raabe@mandiant.com
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - Communication::Interprocess Communication::Create Pipe [C0003.001]
    examples:
      - Practical Malware Analysis Lab 03-02.dll_:0x10003a13
  features:
    - or:
      - api: kernel32.CreatePipe
      - api: kernel32.CreateNamedPipe
      - api: System.IO.Pipes.AnonymousPipeClientStream::ctor
      - api: System.IO.Pipes.NamedPipeClientStream::ctor
      - api: System.IO.Pipes.AnonymousPipeServerStream::ctor
      - api: System.IO.Pipes.AnonymousPipeServerStreamAcl::Create
      - api: System.IO.Pipes.NamedPipeServerStream::ctor
      - api: System.IO.Pipes.NamedPipeServerStreamAcl::Create
