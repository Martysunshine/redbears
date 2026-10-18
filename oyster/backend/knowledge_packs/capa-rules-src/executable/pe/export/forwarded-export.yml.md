<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/executable/pe/export/forwarded-export.yml -->
rule:
  meta:
    name: forwarded export
    namespace: executable/pe/export
    authors:
      - ronnie.salomonsen@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Execution::Shared Modules [T1129]
    examples:
      - 76FA734236DAA023444DEC26863401DC
  features:
    - characteristic: forwarded export
