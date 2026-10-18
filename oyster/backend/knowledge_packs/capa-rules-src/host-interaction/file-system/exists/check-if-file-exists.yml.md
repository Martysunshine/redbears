<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/exists/check-if-file-exists.yml -->
rule:
  meta:
    name: check if file exists
    namespace: host-interaction/file-system/exists
    authors:
      - moritz.raabe@mandiant.com
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Discovery::File and Directory Discovery [T1083]
    mbc:
      - Discovery::File and Directory Discovery [E1083]
    examples:
      - 31600AD0D1A7EA615690DF111AE36C73:0x401284
  features:
    - or:
      - basic block:
        - and:
          - api: kernel32.GetFileAttributes
          - instruction:
            - mnemonic: cmp
            - number: 0xFFFFFFFF = INVALID_FILE_ATTRIBUTES
      - basic block:
        - and:
          - api: kernel32.GetLastError
          - instruction:
            - mnemonic: cmp
            - number: 2 = ERROR_FILE_NOT_FOUND
      - api: shlwapi.PathFileExists
      - api: System.IO.File::Exists
      - property/read: System.IO.FileSystemInfo::Exists
