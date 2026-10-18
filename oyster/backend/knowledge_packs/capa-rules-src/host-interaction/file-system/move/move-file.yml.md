<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/move/move-file.yml -->
rule:
  meta:
    name: move file
    namespace: host-interaction/file-system/move
    authors:
      - moritz.raabe@mandiant.com
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - File System::Move File [C0063]
    examples:
      - Practical Malware Analysis Lab 01-04.exe_:0x401350
  features:
    - or:
      - api: kernel32.MoveFile
      - api: kernel32.MoveFileEx
      - api: MoveFileWithProgress
      - api: MoveFileTransacted
      - api: rename
      - api: _wrename
      - api: System.IO.FileInfo::MoveTo
      - api: System.IO.File::Move
      - basic block:
        - and:
          - number: 1 = FO_MOVE
          - or:
            - api: kernel32.SHFileOperation
      - call:
        - and:
          - number: 1 = FO_MOVE
          - api: kernel32.SHFileOperation
