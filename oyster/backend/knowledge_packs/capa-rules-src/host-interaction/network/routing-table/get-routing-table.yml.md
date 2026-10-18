<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/network/routing-table/get-routing-table.yml -->
rule:
  meta:
    name: get routing table
    namespace: host-interaction/network/routing-table
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: instruction
      dynamic: call
    att&ck:
      - Discovery::System Network Configuration Discovery [T1016]
    references:
      - https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getipforwardtable
      - https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2
      - https://github.com/T04R/collection/blob/main/evasion/03.Local-admin/EPP-comms/netblk-printroute/implant.cpp
    examples:
      - b1133d7e5599beefe992a127f6e9704176a13b7e86b4db45c3b61cf25a60d414:0x140001000
  features:
    - or:
      - api: iphlpapi.GetIpForwardTable
      - api: iphlpapi.GetIpForwardTable2
