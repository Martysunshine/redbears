<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/create/execute-command.yml -->
rule:
  meta:
    name: execute command
    namespace: host-interaction/process/create
    authors:
      - "@mr-tz"
    scopes:
      static: function
      dynamic: call
    mbc:
      - Process::Create Process [C0017]
    examples:
      - e353d3fbfb5c3738a77a622adff9a416:0x401626
  features:
    - or:
      - api: system
      - api: _system
      - api: wsystem
      - api: _wsystem
