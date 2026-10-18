<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/write/clear-file-content.yml -->
rule:
  meta:
    name: clear file content
    namespace: host-interaction/file-system/write
    authors:
      - jakeperalta7
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - File System::Writes File [C0052]
    examples:
      - e3a6fbbc9b315141da37e5abbae05bf20aa9f48d5f569c6353360f59a0315245:0x140001450
  features:
    - and:
      - api: kernel32.SetEndOfFile
      - not:
        - api: kernel32.SetFilePointer
