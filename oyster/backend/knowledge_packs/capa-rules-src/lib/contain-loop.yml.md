<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/lib/contain-loop.yml -->
rule:
  meta:
    name: contain loop
    authors:
      - moritz.raabe@mandiant.com
    lib: true
    scopes:
      static: function
      dynamic: unsupported  # requires characteristic features
    examples:
      - 08AC667C65D36D6542917655571E61C8:0x406EAA
  features:
    - or:
      - characteristic: loop
      - characteristic: tight loop
      - characteristic: recursive call
