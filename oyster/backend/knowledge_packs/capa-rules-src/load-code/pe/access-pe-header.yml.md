<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/load-code/pe/access-pe-header.yml -->
rule:
  meta:
    name: access PE header
    namespace: load-code/pe
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Execution::Shared Modules [T1129]
    examples:
      - 563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299:0x1400018E0
  features:
    - and:
      - os: windows
      - or:
        - api: RtlImageNtHeader
        - api: RtlImageNtHeaderEx
