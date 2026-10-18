<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/authentication-process/act-as-credential-manager-dll.yml -->
rule:
  meta:
    name: act as credential manager DLL
    namespace: persistence/authentication-process
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Persistence::Modify Authentication Process::Network Provider DLL [T1556.008]
    examples:
      - b283415c9df06f0e53b7d452d3e5c840c5bd7a6ce734a30bae4a869a57974a0e
  features:
    - and:
      - export: NPGetCaps
      - or:
        - export: NPLogonNotify
        - export: NPPasswordChangeNotify
