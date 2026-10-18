<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/load-code/shellcode/spawn-thread-to-rwx-shellcode.yml -->
rule:
  meta:
    name: spawn thread to RWX shellcode
    namespace: load-code/shellcode
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Memory::Allocate Memory [C0007]
      - Process::Create Thread [C0038]
    examples:
      - Practical Malware Analysis Lab 19-02.exe_:0x401230
  features:
    - and:
      - match: allocate or change RWX memory
      - match: create thread
