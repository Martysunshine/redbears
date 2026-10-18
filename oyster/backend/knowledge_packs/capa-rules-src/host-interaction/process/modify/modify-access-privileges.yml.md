<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/modify/modify-access-privileges.yml -->
rule:
  meta:
    name: modify access privileges
    namespace: host-interaction/process/modify
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: instruction
      dynamic: call
    att&ck:
      - Privilege Escalation::Access Token Manipulation [T1134]
    examples:
      - 9324D1A8AE37A36AE560C37448C9705A:0x403BE0
  features:
    - and:
      - api: advapi32.AdjustTokenPrivileges
