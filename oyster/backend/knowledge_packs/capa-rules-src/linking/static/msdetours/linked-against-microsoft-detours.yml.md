<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/linking/static/msdetours/linked-against-microsoft-detours.yml -->
rule:
  meta:
    name: linked against Microsoft Detours
    namespace: linking/static/msdetours
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Defense Evasion::Hijack Execution Flow [T1574]
    references:
      - https://github.com/microsoft/Detours
    examples:
      - 071F2D1C4C2201EE95FFE2AA965000F5F615A11A12D345E33B9FB060E5597740
  features:
    - or:
      - section: .detourc
      - section: .detourd
