<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/service/list/enumerate-services.yml -->
rule:
  meta:
    name: enumerate services
    namespace: host-interaction/service/list
    authors:
      - moritz.raabe@mandiant.com
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Discovery::System Service Discovery [T1007]
    examples:
      - Practical Malware Analysis Lab 05-01.dll_:0x1000B823
  features:
    - or:
      - api: advapi32.EnumServicesStatus
      - api: advapi32.EnumServicesStatusEx
      - api: advapi32.EnumDependentServices
