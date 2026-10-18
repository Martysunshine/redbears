<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/network/traffic/filter/register-network-filter-via-wfp-api.yml -->
rule:
  meta:
    name: register network filter via WFP API
    namespace: host-interaction/network/traffic/filter
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Impact::Data Manipulation::Transmitted Data Manipulation [T1565.002]
    examples:
      - 493167E85E45363D09495D0841C30648:0x404220
  features:
    - and:
      - api: fwpkclnt.FwpmFilterAdd0
