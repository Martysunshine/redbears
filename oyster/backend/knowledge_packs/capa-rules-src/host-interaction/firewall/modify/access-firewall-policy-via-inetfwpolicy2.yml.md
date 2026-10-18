<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/firewall/modify/access-firewall-policy-via-inetfwpolicy2.yml -->
rule:
  meta:
    name: access firewall policy via INetFwPolicy2
    namespace: host-interaction/firewall/modify
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::Software Discovery::Security Software Discovery [T1518.001]
    references:
      - https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2
    examples:
      - a210a5daaf487fe6c8bbaf906abce749042f15890d60b09c6cb333e54958663b:0x180002D60
  features:
    - and:
      - api: ole32.CoCreateInstance
      - bytes: 7f c9 b3 e2 e1 6a ac 41 81 7a f6 f9 21 66 d7 dd = CLSID_FwPolicy2
      - bytes: 47 50 32 98 71 c6 74 41 8d 81 de fc d3 f0 31 86 = IID_INetFwPolicy2
