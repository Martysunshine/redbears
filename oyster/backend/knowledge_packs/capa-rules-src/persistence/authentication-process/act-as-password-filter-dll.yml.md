<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/authentication-process/act-as-password-filter-dll.yml -->
rule:
  meta:
    name: act as password filter DLL
    namespace: persistence/authentication-process
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Persistence::Modify Authentication Process::Password Filter DLL [T1556.002]
    examples:
      - 4f08636da3941f6f1e70ac2bf449b69e2ddbdc23dac58fd7eab9c5fdce6a4960
  features:
    - and:
      - export: InitializeChangeNotify
      - export: PasswordChangeNotify
      - export: PasswordFilter
