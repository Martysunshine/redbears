<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/service/stop/stop-service.yml -->
rule:
  meta:
    name: stop service
    namespace: host-interaction/service/stop
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Create or Modify System Process::Windows Service [T1543.003]
      - Impact::Service Stop [T1489]
    examples:
      - E544A4D616B60147D9774B48C2B65EF2:0x402140
  features:
    - and:
      - optional:
        - match: get service handle
      - or:
        - basic block:
          - and:
            - number: 0x1 = SERVICE_CONTROL_STOP
            - or:
              - api: advapi32.ControlService
              - api: advapi32.ControlServiceEx
        - call:
          - and:
            - number: 0x1 = SERVICE_CONTROL_STOP
            - or:
              - api: advapi32.ControlService
              - api: advapi32.ControlServiceEx
