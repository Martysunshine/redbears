<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/map-section-object.yml -->
rule:
  meta:
    name: map section object
    namespace: host-interaction/process
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    examples:
      - 61908f4d70ce6f16173e76aa42a8c25a:0x4018F0
  features:
    - and:
      - os: windows
      - or:
        - api: NtMapViewOfSection
        - api: ZwMapViewOfSection
      - optional:
        - api: NtUnmapViewOfSection
        - api: ZwUnmapViewOfSection
        - match: create or open section object
