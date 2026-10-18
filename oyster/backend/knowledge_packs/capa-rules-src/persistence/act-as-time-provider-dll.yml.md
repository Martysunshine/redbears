<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/act-as-time-provider-dll.yml -->
rule:
  meta:
    name: act as Time Provider DLL
    namespace: persistence
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Persistence::Boot or Logon Autostart Execution::Time Providers [T1547.003]
    references:
      - https://learn.microsoft.com/en-gb/windows/win32/sysinfo/creating-a-time-provider
    examples:
      - d68ce802ef22a1bafc00c2e6675959f177ce8aed91003a053ac0c888bec42c54
  features:
    - or:
      - export: TimeProvClose
      - export: TimeProvCommand
      - export: TimeProvOpen
