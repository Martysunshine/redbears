<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/session/get-user-security-identifier.yml -->
# generated using capa explorer for IDA Pro
rule:
  meta:
    name: get user security identifier
    namespace: host-interaction/session
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    att&ck:
      - Discovery::Account Discovery [T1087]
    examples:
      - mimikatz.exe_:0x40DC42
  features:
    - or:
      - api: advapi32.LookupAccountName
      - api: advapi32.LsaLookupNames
      - api: advapi32.LsaLookupNames2
