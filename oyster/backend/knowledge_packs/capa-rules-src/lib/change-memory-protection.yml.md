<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/lib/change-memory-protection.yml -->
rule:
  meta:
    name: change memory protection
    authors:
      - "@mr-tz"
    lib: true
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Memory::Change Memory Protection [C0008]
    examples:
      - Practical Malware Analysis Lab 11-02.dll_:0x10001203
  features:
    - or:
      - api: kernel32.VirtualProtect
      - api: kernel32.VirtualProtectEx
      - api: NtProtectVirtualMemory
      - api: ZwProtectVirtualMemory
      - basic block:
        - and:
          - match: link function at runtime on Windows
          - or:
            - string: "VirtualProtect"
            - string: "VirtualProtectEx"
            - string: "NtProtectVirtualMemory"
            - string: "ZwProtectVirtualMemory"
