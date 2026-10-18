<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/lib/get-service-handle.yml -->
rule:
  meta:
    name: get service handle
    authors:
      - moritz.raabe@mandiant.com
    lib: true
    scopes:
      static: function
      dynamic: call
    examples:
      - Practical Malware Analysis Lab 03-02.dll_:0x10004706
  features:
    - or:
      - api: advapi32.CreateService
      - api: advapi32.OpenService
