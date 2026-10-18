<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/registry/query-registry-key-via-offline-registry-library.yml -->
rule:
  meta:
    name: query registry key via offline registry library
    namespace: host-interaction/registry
    authors:
      - johnk3r
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Discovery::Query Registry [T1012]
    mbc:
      - Operating System::Registry::Query Registry Value [C0036.006]
    examples:
      - 5fbbfeed28b258c42e0cfeb16718b31c:0x42388C
  features:
    - and:
      - api: ORGetValue
