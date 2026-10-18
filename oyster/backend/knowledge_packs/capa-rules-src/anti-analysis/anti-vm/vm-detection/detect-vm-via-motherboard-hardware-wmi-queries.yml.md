<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-vm/vm-detection/detect-vm-via-motherboard-hardware-wmi-queries.yml -->
# generated using capa explorer for IDA Pro
rule:
  meta:
    name: detect VM via motherboard hardware WMI queries
    namespace: anti-analysis/anti-vm/vm-detection
    authors:
      - anders.vejlby@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]
    mbc:
      - Anti-Behavioral Analysis::Virtual Machine Detection::Unique Hardware/Firmware Check [B0009.023]
    examples:
      - 32B3678F8C29437E9EA10EAB10194F66:0x4035e0
  features:
    - and:
      - string: "Win32_BaseBoard"
      - string: "Virtual"
      - string: "Product"
