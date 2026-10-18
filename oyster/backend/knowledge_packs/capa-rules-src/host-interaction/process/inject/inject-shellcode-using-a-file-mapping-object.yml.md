<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/inject/inject-shellcode-using-a-file-mapping-object.yml -->
rule:
  meta:
    name: inject shellcode using a file mapping object
    namespace: host-interaction/process/inject
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Process Injection [T1055]
    mbc:
      - Defense Evasion::Process Injection [E1055]
    references:
      - https://github.com/antonioCoco/Mapping-Injection/tree/1.1
      - https://github.com/Kara-4search/MappingInjection_CSharp
    examples:
      - 8b1682c85612db9f62eb3600a90b54e83117bb756a7456c9f82ccdcb0bf4b7e4:0x401000
  features:
    - and:
      - match: create thread
      - api: CreateFileMapping
      - api: MapViewOfFile
      - api: MapViewOfFileNuma2
