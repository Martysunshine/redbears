<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/service/start/start-service.yml -->
rule:
  meta:
    name: start service
    namespace: host-interaction/service/start
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Create or Modify System Process::Windows Service [T1543.003]
    examples:
      - E544A4D616B60147D9774B48C2B65EF2:0x401FA0
  features:
    - and:
      - optional:
        - match: get service handle
      - api: advapi32.StartService
