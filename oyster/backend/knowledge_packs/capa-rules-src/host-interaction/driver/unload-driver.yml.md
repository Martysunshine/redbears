<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/driver/unload-driver.yml -->
rule:
  meta:
    name: unload driver
    namespace: host-interaction/driver
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    att&ck:
      - Persistence::Create or Modify System Process::Windows Service [T1543.003]
    examples:
      - 31cee4f66cf3b537e3d2d37a71f339f4:0x1400044ce
  features:
    - or:
      - api: NtUnloadDriver
      - api: ZwUnloadDriver
