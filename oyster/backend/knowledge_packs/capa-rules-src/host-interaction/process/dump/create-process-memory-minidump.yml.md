<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/process/dump/create-process-memory-minidump.yml -->
# generated using capa explorer for IDA Pro
rule:
  meta:
    name: create process memory minidump
    namespace: host-interaction/process/dump
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - File System::Writes File [C0052]
    examples:
      - 91a12a4cf437589ba70b1687f5acad19:0x43E1C9
  features:
    - or:
      - api: dbghelp.MiniDumpWriteDump
