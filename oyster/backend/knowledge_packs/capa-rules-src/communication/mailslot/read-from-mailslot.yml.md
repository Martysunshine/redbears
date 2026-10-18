<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/mailslot/read-from-mailslot.yml -->
rule:
  meta:
    name: read from mailslot
    namespace: communication/mailslot
    authors:
      - nick.simonian@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::Interprocess Communication [C0003]
    references:
      - https://learn.microsoft.com/en-us/windows/win32/ipc/reading-from-a-mailslot
    examples:
      - CC870A35C6840987DCB8C2DD46BC230A:0x4010F0
  features:
    - and:
      - api: kernel32.GetMailslotInfo
      - or:
        - api: kernel32.ReadFile
        - api: kernel32.ReadFileEx
