<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/log/clfs/read-data-from-clfs-log-container.yml -->
# generated using capa explorer for IDA Pro
rule:
  meta:
    name: read data from CLFS log container
    namespace: host-interaction/log/clfs/read
    authors:
      - blaine.stancill@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Discovery::File and Directory Discovery::Log File [E1083.m01]
    references:
      - https://docs.microsoft.com/en-us/windows/win32/api/clfsw32/
      - https://github.com/libyal/libfsclfs/blob/main/documenation/Common%20Log%20File%20System%20(CLFS).asciidoc
    examples:
      - 91B08896FBDA9EDB8B6F93A6BC811EC6:0x1800018F6
  features:
    - and:
      - api: clfsw32.CreateLogFile
      - api: clfsw32.CreateLogMarshallingArea
      - or:
        - api: clfsw32.ReadLogRecord
        - api: clfsw32.ReadNextLogRecord
