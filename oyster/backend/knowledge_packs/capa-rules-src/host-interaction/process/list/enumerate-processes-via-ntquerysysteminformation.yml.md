<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/list/enumerate-processes-via-ntquerysysteminformation.yml -->
rule:
  meta:
    name: enumerate processes via NtQuerySystemInformation
    namespace: host-interaction/process/list
    authors:
      - "@_re_fox"
    scopes:
      static: basic block
      dynamic: call
    att&ck:
      - Discovery::Process Discovery [T1057]
      - Discovery::Software Discovery [T1518]
    examples:
      - 31bd8dd48ac0de3d4da340bf29f4d280:0x00401be3
  features:
    - and:
      - number: 0x5 = SYSTEM_PROCESS_INFORMATION
      - or:
        - api: NtQuerySystemInformation
        - api: NtQuerySystemInformationEx
        - api: ZwQuerySystemInformation
        - api: ZwQuerySystemInformationEx
