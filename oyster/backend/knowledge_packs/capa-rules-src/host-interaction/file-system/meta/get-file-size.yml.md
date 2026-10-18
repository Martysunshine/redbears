<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/meta/get-file-size.yml -->
rule:
  meta:
    name: get file size
    namespace: host-interaction/file-system/meta
    authors:
      - michael.hunhoff@mandiant.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Discovery::File and Directory Discovery [T1083]
    mbc:
      - Discovery::File and Directory Discovery [E1083]
    examples:
      - mimikatz.exe_:0x40630D
  features:
    - or:
      - api: kernel32.GetFileSize
      - api: kernel32.GetFileSizeEx
      - property/read: System.IO.FileInfo::Length
