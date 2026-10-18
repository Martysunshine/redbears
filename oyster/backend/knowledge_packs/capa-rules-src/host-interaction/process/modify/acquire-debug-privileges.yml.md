<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/modify/acquire-debug-privileges.yml -->
rule:
  meta:
    name: acquire debug privileges
    namespace: host-interaction/process/modify
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    att&ck:
      - Privilege Escalation::Access Token Manipulation [T1134]
    examples:
      - Practical Malware Analysis Lab 01-04.exe_:0x401174
  features:
    - or:
      - and:
        - string: "SeDebugPrivilege"
        - optional:
          - match: modify access privileges
      - and:
        - api: RtlAdjustPrivilege
        - number: 20 = SE_DEBUG_PRIVILEGE
