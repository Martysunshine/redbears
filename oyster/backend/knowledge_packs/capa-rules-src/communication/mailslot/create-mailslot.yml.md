<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/mailslot/create-mailslot.yml -->
rule:
  meta:
    name: create mailslot
    namespace: communication/mailslot
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::Interprocess Communication [C0003]
    references:
      - https://learn.microsoft.com/en-us/windows/win32/ipc/mailslots
    examples:
      - af13e7583ed1b27c4ae219e344a37e2b:0x40151D
  features:
    - and:
      - api: kernel32.CreateMailslot
      - optional:
        - api: kernel32.GetMailslotInfo
        - api: kernel32.SetMailslotInfo
