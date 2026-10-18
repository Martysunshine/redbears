<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/registry/delete/delete-registry-value.yml -->
rule:
  meta:
    name: delete registry value
    namespace: host-interaction/registry/delete
    authors:
      - michael.hunhoff@mandiant.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Modify Registry [T1112]
    mbc:
      - Operating System::Registry::Delete Registry Value [C0036.007]
    examples:
      - B5F85C26D7AA5A1FB4AF5821B6B5AB9B:0x4041A0
  features:
    - and:
      - optional:
        - match: create or open registry key
      - or:
        - api: advapi32.RegDeleteValue
        - api: advapi32.RegDeleteKeyValue
        - api: ZwDeleteValueKey
        - api: NtDeleteValueKey
        - api: RtlDeleteRegistryValue
        - api: SHDeleteValue
        - api: SHRegDeleteUSValue
        - api: Microsoft.Win32.RegistryKey::DeleteValue
