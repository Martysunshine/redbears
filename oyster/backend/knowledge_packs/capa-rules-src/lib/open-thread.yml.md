<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/lib/open-thread.yml -->
rule:
  meta:
    name: open thread
    authors:
      - 0x534a@mailbox.org
    lib: true
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Process::Open Thread [C0066]
    examples:
      - 787cbc8a6d1bc58ea169e51e1ad029a637f22560660cc129ab8a099a745bd50e:00502F4C
  features:
    - or:
      - api: kernel32.OpenThread
      - api: NtOpenThread
      - api: ZwOpenThread
