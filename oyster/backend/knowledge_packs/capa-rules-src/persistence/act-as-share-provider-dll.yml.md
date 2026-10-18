<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/act-as-share-provider-dll.yml -->
rule:
  meta:
    name: act as Share Provider DLL
    namespace: persistence
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Persistence::Server Software Component [T1505]
    references:
      - https://www.hexacorn.com/blog/2018/10/14/how-to-find-new-persistence-tricks/
    examples:
      - 7ca4ce02c9d331c2cfdad7329352664c224f02ccfef826a76321831bee1e2191
  features:
    - or:
      - export: ShareProviderInitialize
      - export: ShareProviderUninitialize
      - export: ShareProviderShareAdd
      - export: ShareProviderShareSetInfo
      - export: ShareProviderShareDel
