<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/session/get-token-membership.yml -->
rule:
  meta:
    name: get token membership
    namespace: host-interaction/session
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::System Owner/User Discovery [T1033]
    examples:
      - mimikatz.exe_:0x40DABE
  features:
    - and:
      - api: advapi32.CheckTokenMembership
      - optional:
        - api: advapi32.AllocateAndInitializeSid
        - api: advapi32.FreeSid
