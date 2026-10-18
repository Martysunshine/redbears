<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/filter/unload-minifilter-driver.yml -->
rule:
  meta:
    name: unload minifilter driver
    namespace: host-interaction/filter
    authors:
      - JakePeralta7
    scopes:
      static: basic block
      dynamic: call
    examples:
      - c3ef997d330e65be1e22ba4d2622ece23391c6cfc78b2ee515f3d0c7a3083a79:0x14000161D
  features:
    - api: fltlib.FilterUnload
