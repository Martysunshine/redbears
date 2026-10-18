<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/lib/allocate-or-change-rw-memory.yml -->
rule:
  meta:
    name: allocate or change RW memory
    authors:
      - 0x534a@mailbox.org
      - "@mr-tz"
    lib: true
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Memory::Allocate Memory [C0007]
    examples:
      - Practical Malware Analysis Lab 17-02.dll_:0x1000D10D
  features:
    - and:
      - or:
        - match: allocate memory
        - match: change memory protection
      - or:
        - number: 0x4 = PAGE_READWRITE
        # lea     r9d, [rcx+4]  ; flProtect
        # call    cs:VirtualAlloc
        - instruction:
          - mnemonic: lea
          - offset: 0x4 = PAGE_READWRITE
