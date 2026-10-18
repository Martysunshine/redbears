<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/office/act-as-excel-xll-add-in.yml -->
rule:
  meta:
    name: act as Excel XLL add-in
    namespace: persistence/office
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Persistence::Office Application Startup::Add-ins [T1137.006]
    references:
      - https://learn.microsoft.com/en-us/office/client-developer/excel/xlautoopen
    examples:
      - c29513e5a51dd24ca840f7628b872cba921976cba89dcbffd5028ba15481108c
  features:
    - or:
      - export: xlAutoOpen
