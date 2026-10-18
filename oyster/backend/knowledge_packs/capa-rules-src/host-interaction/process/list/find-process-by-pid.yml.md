<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/list/find-process-by-pid.yml -->
rule:
  meta:
    name: find process by PID
    namespace: host-interaction/process/list
    authors:
      - michael.hunhoff@mandiant.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::Process Discovery [T1057]
    examples:
      - 493167E85E45363D09495D0841C30648:0x404B00
  features:
    - and:
      - or:
        - api: ntoskrnl.PsLookupProcessByProcessId
        - api: System.Diagnostics.Process::GetProcessById
      - optional:
        - api: ntoskrnl.ObfDereferenceObject
