<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/log/winevt/access/access-the-windows-event-log.yml -->
rule:
  meta:
    name: access the Windows event log
    namespace: host-interaction/log/winevt/access
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - Discovery::File and Directory Discovery::Log File [E1083.m01]
    examples:
      - mimikatz.exe_:0x45228B
  features:
    - or:
      - api: OpenEventLog
      - api: ClearEventLog
      - api: OpenBackupEventLog
      - api: ReportEvent
