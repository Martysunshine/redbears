<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/service/modify/modify-service.yml -->
rule:
  meta:
    name: modify service
    namespace: host-interaction/service/modify
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Create or Modify System Process::Windows Service [T1543.003]
      - Execution::System Services::Service Execution [T1569.002]
    examples:
      - 7D16EFD0078F22C17A4BD78B0F0CC468:0x401000
  features:
    - and:
      - optional:
        - match: get service handle
      - or:
        - api: advapi32.ChangeServiceConfig
        - api: advapi32.ChangeServiceConfig2
