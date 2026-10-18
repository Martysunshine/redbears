<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/session/get-logon-sessions.yml -->
rule:
  meta:
    name: get logon sessions
    namespace: host-interaction/session
    authors:
      - awillia2@cisco.com
    description: Looks for imported Windows APIs being called to enumerate user sessions.
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::Account Discovery [T1087]
    examples:
      - 9B7CCAA2AE6A5B96E3110EBCBC4311F6:0x1001C1AC
  features:
    - and:
      - api: secur32.LsaEnumerateLogonSessions
      - optional:
        - api: secur32.LsaGetLogonSessionData
