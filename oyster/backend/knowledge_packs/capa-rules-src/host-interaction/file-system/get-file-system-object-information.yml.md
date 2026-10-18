<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/get-file-system-object-information.yml -->
rule:
  meta:
    name: get file system object information
    namespace: host-interaction/file-system
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    att&ck:
      - Discovery::File and Directory Discovery [T1083]
    examples:
      - 50D5EE1CE2CA5E30C6B1019EE64EEEC2:0x403538
  features:
    - or:
      - api: SHGetFileInfo
