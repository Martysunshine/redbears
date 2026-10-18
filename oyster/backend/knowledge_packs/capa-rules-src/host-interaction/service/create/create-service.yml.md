<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/service/create/create-service.yml -->
rule:
  meta:
    name: create service
    namespace: host-interaction/service/create
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Create or Modify System Process::Windows Service [T1543.003]
      - Execution::System Services::Service Execution [T1569.002]
    examples:
      - Practical Malware Analysis Lab 03-02.dll_:0x10004706
  features:
    - or:
      - and:
        - api: advapi32.CreateService
        - optional:
          - api: advapi32.OpenSCManager
      - and:
        - or:
          - substring: "sc.exe create"
          - substring: "sc create"
        - optional:
          - substring: "binpath="
