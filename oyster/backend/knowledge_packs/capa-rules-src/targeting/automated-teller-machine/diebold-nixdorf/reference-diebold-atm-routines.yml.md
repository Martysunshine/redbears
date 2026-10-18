<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/targeting/automated-teller-machine/diebold-nixdorf/reference-diebold-atm-routines.yml -->
rule:
  meta:
    name: reference Diebold ATM routines
    namespace: targeting/automated-teller-machine/diebold-nixdorf
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: file
      dynamic: file
    references:
      - https://www.mandiant.com/resources/new-ploutus-variant
    examples:
      - b2ad4409323147b63e370745e5209996
  features:
    - or:
      - string: "DBD_AdvFuncDisp"
        description: dispenser function
      - string: "DBD_EPP4"
        description: pin pad function
