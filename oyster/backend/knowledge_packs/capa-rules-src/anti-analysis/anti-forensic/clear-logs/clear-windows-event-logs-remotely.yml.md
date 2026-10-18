<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-forensic/clear-logs/clear-windows-event-logs-remotely.yml -->
rule:
  meta:
    name: clear Windows event logs remotely
    namespace: anti-analysis/anti-forensic/clear-logs
    authors:
      - 99.elad.levi@gmail.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Indicator Removal::Clear Windows Event Logs [T1070.001]
    references:
      - https://github.com/getel-arch/ClearLogsRemotely
    examples:
      - 4f509bdfe5a2fe4320cdc070eedc0a72e12cc08f43d60a7701305b3d1408102b:0x1400014de
  features:
    - and:
      - api: wevtapi.EvtOpenSession
      - api: wevtapi.EvtClearLog
