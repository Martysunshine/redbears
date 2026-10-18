<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/startup-folder/write-file-to-startup-folder.yml -->
rule:
  meta:
    name: write file to startup folder
    namespace: persistence/startup-folder
    authors:
      - matthew.williams@mandiant.com
      - j.j.vannielen@utwente.nl
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]
    examples:
      - 07F7846BBCDA782E5639292AD93907EB:0x401040
  features:
    - or:
      - and:
        - match: get startup folder
        - or:
          - match: copy file
          - match: move file
          - match: write file on Windows
      - call:
        - and:
          - string: /Start Menu\\Programs\\Startup/i
          - or:
            - match: copy file
            - match: move file
            - match: write file on Windows
