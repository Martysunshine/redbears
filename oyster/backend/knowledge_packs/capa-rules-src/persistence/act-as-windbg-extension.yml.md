<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/act-as-windbg-extension.yml -->
rule:
  meta:
    name: act as WinDbg extension
    namespace: persistence
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Persistence::Server Software Component [T1505]
    references:
      - https://www.codeproject.com/Articles/6522/Debug-Tutorial-Part-4-Writing-WINDBG-Extensions
    examples:
      - 36f506a34b99bf4c199b3c9ec8aa02bd631feafdca20e69e33e714c269ddb8c5
  features:
    - or:
      - export: ExtensionApiVersion
      - export: WinDbgExtensionDllInit
