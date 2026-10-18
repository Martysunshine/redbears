<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/service/continue-service.yml -->
rule:
  meta:
    name: continue service
    namespace: host-interaction/service
    authors:
      - "@mr-tz"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Create or Modify System Process::Windows Service [T1543.003]
    examples:
      - Practical Malware Analysis Lab 17-02.dll_:0x1000bd79
  features:
    - and:
      - optional:
        - match: get service handle
      - or:
        - basic block:
          - and:
            - number: 0x3 = SERVICE_CONTROL_CONTINUE
            - or:
              - api: advapi32.ControlService
              - api: advapi32.ControlServiceEx
        - call:
          - and:
            - number: 0x3 = SERVICE_CONTROL_CONTINUE
            - or:
              - api: advapi32.ControlService
              - api: advapi32.ControlServiceEx
