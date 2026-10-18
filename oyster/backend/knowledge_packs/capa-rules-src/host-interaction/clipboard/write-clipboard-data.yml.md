<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/clipboard/write-clipboard-data.yml -->
rule:
  meta:
    name: write clipboard data
    namespace: host-interaction/clipboard
    authors:
      - michael.hunhoff@mandiant.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Impact::Clipboard Modification [E1510]
    references:
      - https://learn.microsoft.com/en-us/windows/win32/dataxchg/using-the-clipboard
    examples:
      - 6F99A2C8944CB02FF28C6F9CED59B161:0x403180
  features:
    - and:
      - optional:
        - match: open clipboard
        - api: user32.EmptyClipboard
        - api: System.Windows.Forms.Clipboard::Clear
      - or:
        - api: user32.SetClipboardData
        - api: System.Windows.Forms.Clipboard::SetAudio
        - api: System.Windows.Forms.Clipboard::SetData
        - api: System.Windows.Forms.Clipboard::SetDataObject
        - api: System.Windows.Forms.Clipboard::SetFileDropList
        - api: System.Windows.Forms.Clipboard::SetImage
        - api: System.Windows.Forms.Clipboard::SetText
