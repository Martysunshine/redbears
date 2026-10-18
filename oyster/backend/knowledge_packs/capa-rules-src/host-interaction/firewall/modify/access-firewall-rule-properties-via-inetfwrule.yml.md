<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/firewall/modify/access-firewall-rule-properties-via-inetfwrule.yml -->
rule:
  meta:
    name: access firewall rule properties via INetFwRule
    namespace: host-interaction/firewall/modify
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::Software Discovery::Security Software Discovery [T1518.001]
    references:
      - https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule
    examples:
      - a210a5daaf487fe6c8bbaf906abce749042f15890d60b09c6cb333e54958663b:0x180002D60
  features:
    - and:
      - api: ole32.CoCreateInstance
      - bytes: 3e c4 5b 2c 69 33 33 4c ab 0c be 94 69 67 7a f4 = CLSID_FwRule
      - bytes: 27 0d 23 af ba ba 42 4e ac ed f5 24 f2 2c fc e2 = IID_INetFwRule
