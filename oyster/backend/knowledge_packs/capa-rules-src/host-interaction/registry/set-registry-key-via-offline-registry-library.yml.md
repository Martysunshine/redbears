<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/registry/set-registry-key-via-offline-registry-library.yml -->
rule:
  meta:
    name: set registry key via offline registry library
    namespace: host-interaction/registry
    authors:
      - johnk3r
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Modify Registry [T1112]
    mbc:
      - Operating System::Registry::Set Registry Key [C0036.001]
    examples:
      - 5fbbfeed28b258c42e0cfeb16718b31c:0x43A6C8
  features:
    - and:
      - api: ORSetValue
      - optional:
        - api: ORSaveHive
