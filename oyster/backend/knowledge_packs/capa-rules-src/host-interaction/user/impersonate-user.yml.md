<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/user/impersonate-user.yml -->
rule:
  meta:
    name: impersonate user
    namespace: host-interaction/user
    authors:
      - michael.hunhoff@mandiant.com
      - 99.elad.levi@gmail.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Privilege Escalation::Access Token Manipulation::Token Impersonation/Theft [T1134.001]
    examples:
      - bf9a888e226d8396e84e042732daf32b8c1df8fd675eb128e8da3f0d7768bea5:0x140001896
  features:
    - or:
      - api: advapi32.LogonUser
      - and:
        - api: userenv.LoadUserProfile
        - optional:
          - api: advapi32.GetUserName
          - api: advapi32.GetUserNameEx
      - and:
        - api: advapi32.OpenProcessToken
        - or:
          - api: advapi32.DuplicateToken
          - api: advapi32.DuplicateTokenEx
        - api: advapi32.CreateProcessWithToken
        - optional:
          - match: acquire debug privileges
          - match: enumerate processes
