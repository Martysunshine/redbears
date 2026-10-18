<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/registry/open-registry-key-via-offline-registry-library.yml -->
rule:
  meta:
    name: open registry key via offline registry library
    namespace: host-interaction/registry
    authors:
      - johnk3r
    scopes:
      static: function
      dynamic: call
    mbc:
      - Operating System::Registry::Open Registry Key [C0036.003]
    examples:
      - 5fbbfeed28b258c42e0cfeb16718b31c:0x4071E1
  features:
    - or:
      - api: OROpenHive
      - api: OROpenKey
