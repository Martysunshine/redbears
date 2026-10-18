<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/autohotkey/compiled-with-autohotkey.yml -->
rule:
  meta:
    name: compiled with AutoHotKey
    namespace: compiler/autohotkey
    authors:
      - awillia2@cisco.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Execution::Command and Scripting Interpreter [T1059]
    references:
      - https://www.trendmicro.com/en_us/research/20/l/stealth-credential-stealer-targets-us-canadian-bank-customers.html
      - https://en.wikipedia.org/wiki/AutoHotkey
    examples:
      - 92D8EA10EA30E8B534334A1C9857A455
  features:
    - and:
      - string: ">AUTOHOTKEY SCRIPT<"
      - string: "AutoHotkeyGUI"
