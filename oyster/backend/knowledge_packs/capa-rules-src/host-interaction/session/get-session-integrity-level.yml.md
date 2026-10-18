<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/session/get-session-integrity-level.yml -->
rule:
  meta:
    name: get session integrity level
    namespace: host-interaction/session
    authors:
      - michael.hunhoff@mandiant.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::System Owner/User Discovery [T1033]
    examples:
      - 9879D201DC5ACA863F357184CD1F170E:0x10003643
  features:
    - or:
      - api: shell32.IsUserAnAdmin
      - and:
        - api: System.Security.Principal.WindowsIdentity::GetCurrent
        - number: 0x220 = BUILTIN\Administrators
        - api: System.Security.Principal.WindowsPrincipal::IsInRole
