<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/authentication-process/act-as-subauthentication-package-dll.yml -->
rule:
  meta:
    name: act as SubAuthentication Package DLL
    namespace: persistence/authentication-process
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Persistence::Boot or Logon Autostart Execution::Authentication Package [T1547.002]
    references:
      - https://learn.microsoft.com/en-us/windows/win32/secauthn/subauthentication-packages
    examples:
      - 36f506a34b99bf4c199b3c9ec8aa02bd631feafdca20e69e33e714c269ddb8c5
  features:
    - or:
      - export: Msv1_0SubAuthenticationFilter
      - export: Msv1_0SubAuthenticationRoutine
      - export: Msv1_0SubAuthenticationRoutineEx
      - export: Msv1_0SubAuthenticationRoutineGeneric
