<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/service/query-service-configuration.yml -->
rule:
  meta:
    name: query service configuration
    namespace: host-interaction/service
    authors:
      - "@mr-tz"
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Discovery::System Service Discovery [T1007]
    examples:
      - Practical Malware Analysis Lab 17-02.dll_:0x1000bf52
  features:
    - or:
      - api: advapi32.QueryServiceConfigA
      - api: advapi32.QueryServiceConfig2A
