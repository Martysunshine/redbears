<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/bootloader/disable-code-signing.yml -->
rule:
  meta:
    name: disable code signing
    namespace: host-interaction/bootloader
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Subvert Trust Controls::Code Signing Policy Modification [T1553.006]
    examples:
      - 0596C4EA5AA8DEF47F22C85D75AACA95:0x10710B3  # old Necurs rootkit
  features:
    - and:
      - match: host-interaction/process/create
      - string: /^bcdedit(\.exe)? -set TESTSIGNING ON/i
