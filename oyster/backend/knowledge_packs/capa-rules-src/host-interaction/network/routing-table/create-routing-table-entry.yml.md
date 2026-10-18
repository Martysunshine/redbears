<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/network/routing-table/create-routing-table-entry.yml -->
rule:
  meta:
    name: create routing table entry
    namespace: host-interaction/network/routing-table
    authors:
      - jakubjozwiak@google.com
    scopes:
      static: instruction
      dynamic: call
    references:
      - https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-createipforwardentry
      - https://github.com/T04R/collection/blob/main/evasion/03.Local-admin/EPP-comms/netblk-route/implant.cpp
    examples:
      - de07bd6e3ade9e4d8a36032a23de11a372bd93d39a6ef95d849e3f6f7ebac6e5:0x140001000
  features:
    - or:
      - api: iphlpapi.CreateIpForwardEntry
