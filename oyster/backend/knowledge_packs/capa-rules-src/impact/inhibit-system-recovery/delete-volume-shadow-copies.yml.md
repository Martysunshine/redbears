<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/impact/inhibit-system-recovery/delete-volume-shadow-copies.yml -->
rule:
  meta:
    name: delete volume shadow copies
    namespace: impact/inhibit-system-recovery
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Impact::Inhibit System Recovery [T1490]
      - Defense Evasion::Indicator Removal::File Deletion [T1070.004]
    mbc:
      - Impact::Data Destruction::Delete Shadow Copies [E1485.m04]
    examples:
      - B87E9DD18A5533A09D3E48A7A1EFBCF6:0x140006AF0
  features:
    - or:
      - string: /vssadmin.* delete shadows/i
      - string: /vssadmin.* resize shadowstorage/i
      - string: /wmic.* shadowcopy delete/i
