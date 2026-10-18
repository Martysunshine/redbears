<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/filter/start-minifilter-driver.yml -->
rule:
  meta:
    name: start minifilter driver
    namespace: host-interaction/filter
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Hardware::Load Driver::Minifilter [C0023.001]
    references:
      - https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts
    examples:
      - B5F85C26D7AA5A1FB4AF5821B6B5AB9B:0x406360
  features:
    - and:
      - api: FltStartFiltering
