<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/act-as-dhcp-server-callout-dll.yml -->
rule:
  meta:
    name: act as DHCP server callout DLL
    namespace: persistence
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Persistence::Server Software Component [T1505]
    references:
      - https://learn.microsoft.com/en-gb/previous-versions/windows/desktop/dhcp/how-the-dhcp-server-api-operates
    examples:
      - 36f506a34b99bf4c199b3c9ec8aa02bd631feafdca20e69e33e714c269ddb8c5
  features:
    - or:
      - export: DhcpServerCalloutEntry
