<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/lib/create-or-open-section-object.yml -->
rule:
  meta:
    name: create or open section object
    authors:
      - william.ballenthin@mandiant.com
    lib: true
    scopes:
      static: function
      dynamic: span of calls
    examples:
      - daa13ae302fe8b618ddbf590537443ef:0x401116
  features:
    - and:
      - os: windows
      - or:
        - api: NtCreateSection
        - api: ZwCreateSection
        - api: NtOpenSection
        - api: ZwOpenSection
