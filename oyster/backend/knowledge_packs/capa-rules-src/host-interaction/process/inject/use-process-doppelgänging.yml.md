<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/inject/use-process-doppelgänging.yml -->
rule:
  meta:
    name: use process Doppelgänging
    namespace: host-interaction/process/inject
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Defense Evasion::Process Injection::Process Doppelgänging [T1055.013]
    examples:
      # proc_doppel64.exe from https://github.com/hasherezade/process_doppelganging/releases/tag/0.2
      - A5D66324DAAEE5672B913AA461D4BD3A
  features:
    - and:
      - substring: "CreateFileTransacted"
      - or:
        - string: "ZwCreateSection"
        - string: "NtCreateSection"
      - string: "RollbackTransaction"
