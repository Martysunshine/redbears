<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/gui/session/wallpaper/change-the-wallpaper.yml -->
rule:
  meta:
    name: change the wallpaper
    namespace: host-interaction/gui/session
    authors:
      - "@_re_fox"
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Operating System::Wallpaper [C0035]
    examples:
      - 5dd0b130d5c3d40c69e3972f39fd7d62:0x45AC6F
  features:
    - and:
      - api: SystemParametersInfo
      - number: 0x14 = SPI_SETDESKWALLPAPER
      - number: 0x3 = SPIF_SENDWININICHANGE | SPIF_UPDATEINIFILE
