<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/lib/open-process.yml -->
rule:
  meta:
    name: open process
    authors:
      - 0x534a@mailbox.org
    lib: true
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Process::Open Process [C0065]
    examples:
      - Practical Malware Analysis Lab 17-02.dll_:0x1000D10D
  features:
    - or:
      - api: kernel32.OpenProcess
      - api: NtOpenProcess
      - api: ZwOpenProcess
