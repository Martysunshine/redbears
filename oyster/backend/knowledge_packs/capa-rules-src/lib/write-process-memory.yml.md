<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/lib/write-process-memory.yml -->
rule:
  meta:
    name: write process memory
    authors:
      - moritz.raabe@mandiant.com
    lib: true
    scopes:
      static: instruction
      dynamic: call
    att&ck:
      - Defense Evasion::Process Injection [T1055]
    examples:
      - 2D3EDC218A90F03089CC01715A9F047F:0x4027CF
  features:
    - or:
      - api: kernel32.WriteProcessMemory
      - api: ntdll.NtWriteVirtualMemory
      - api: ntdll.ZwWriteVirtualMemory
      - api: NtWow64WriteVirtualMemory64
