<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/service/query-service-status.yml -->
rule:
  meta:
    name: query service status
    namespace: host-interaction/service
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Discovery::System Service Discovery [T1007]
    examples:
      - 9DC209F66DA77858E362E624D0BE86B3:0x403C70
  features:
    - or:
      - api: advapi32.QueryServiceStatusEx
      - api: advapi32.QueryServiceStatus
