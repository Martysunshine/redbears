<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/iis/persist-via-iis-module.yml -->
rule:
  meta:
    name: persist via IIS module
    namespace: persistence
    authors:
      - william.ballenthin@mandiant.com
    description: IIS 7.0 introduced modules that provide the same unrestricted access to HTTP requests and responses as ISAPI extensions and filters.
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Persistence::Server Software Component::IIS Components [T1505.004]
    examples:
      - 22d0a2e4c9c2163b2bf5f0e41a2e1762
  features:
    - and:
      - os: windows
      - export: RegisterModule
      - substring: "CHttpModule"
        description: C++ super class provided by Microsoft
