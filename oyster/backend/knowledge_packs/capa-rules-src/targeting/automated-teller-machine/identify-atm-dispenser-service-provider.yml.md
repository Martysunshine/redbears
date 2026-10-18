<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/targeting/automated-teller-machine/identify-atm-dispenser-service-provider.yml -->
rule:
  meta:
    name: identify ATM dispenser service provider
    namespace: targeting/automated-teller-machine
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: file
      dynamic: file
    references:
      - https://doc.axxonsoft.com/confluence/display/atm70en/Configuring+the+connection+to+the+dispenser+service+provider
    examples:
      - b2ad4409323147b63e370745e5209996
      - 1f094dd65be477d15d871e72f0fdce5e
  features:
    - or:
      - string: "CurrencyDispenser1"
        description: NCR
      - string: "CDM30"
        description: Wincor
      - string: "DBD_AdvFuncDisp"
        description: Diebold
