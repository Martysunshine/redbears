<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/lib/create-file-compression-interface-context-on-windows.yml -->
rule:
  meta:
    name: create File Compression Interface context on Windows
    authors:
      - michael.hunhoff@mandiant.com
    lib: true
    scopes:
      static: function
      dynamic: call
    references:
      - https://docs.microsoft.com/en-us/windows/win32/msi/cabinet-files
    examples:
      - 44bad2e2a9e387b86870f009d01833ea4618d2a7cda5f64fa84a19f3bdf4efaf:0x1400028E0
  features:
    - or:
      - api: cabinet.FCICreate
