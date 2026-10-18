<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/persist-via-desktop-autostart.yml -->
rule:
  meta:
    name: persist via .desktop autostart
    namespace: persistence
    authors:
      - joakim@intezer.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Boot or Logon Autostart Execution::XDG Autostart Entries [T1547.013]
    examples:
      - 7351f8a40c5450557b24622417fc478d:0x407D11
  features:
    - and:
      - os: linux
      - match: host-interaction/file-system/write
      - or:
        - string: /\/\.config\/autostart\/.+\.desktop/
        - substring: "/etc/xdg/autostart"
