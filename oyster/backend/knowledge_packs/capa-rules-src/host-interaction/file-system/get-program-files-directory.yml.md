<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/get-program-files-directory.yml -->
rule:
  meta:
    name: get Program Files directory
    namespace: host-interaction/file-system
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    att&ck:
      - Discovery::File and Directory Discovery [T1083]
    examples:
      - BC452CC1128CCF7FA9F76D83CDA79132740414973600FED14509749FE946816E:0x407880
  features:
    - and:
      - or:
        - number: 0x26 = CSIDL_PROGRAM_FILES
        - number: 0x2A = CSIDL_PROGRAM_FILESX86
      - or:
        - api: shell32.SHGetFolderPath
        - api: shell32.SHGetFolderLocation
        - api: shell32.SHGetSpecialFolderPath
        - api: shell32.SHGetSpecialFolderLocation
