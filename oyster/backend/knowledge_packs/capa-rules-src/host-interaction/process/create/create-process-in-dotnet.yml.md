<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/create/create-process-in-dotnet.yml -->
rule:
  meta:
    name: create process in .NET
    namespace: host-interaction/process/create
    authors:
      - moritz.raabe@mandiant.com
      - social.tarang@gmail.com
    scopes:
      static: instruction
      dynamic: call
    mbc:
      - Process::Create Process [C0017]
    examples:
      - 692f7fd6d198e804d6af98eb9e390d61:0x6000003
  features:
    - or:
      - api: System.Diagnostics.Process::Start
