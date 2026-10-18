<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/driver/install-driver.yml -->
rule:
  meta:
    name: install driver
    namespace: host-interaction/driver
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    att&ck:
      - Persistence::Create or Modify System Process::Windows Service [T1543.003]
    mbc:
      - Hardware::Install Driver [C0037]
    references:
      - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/set.htm
    examples:
      - af60700383b75727f5256a0000c1476f:0x1127E
  features:
    - or:
      - api: ntdll.NtLoadDriver
      - api: ZwLoadDriver
      - and:
        - number: 38 = SystemLoadAndCallImage
        - or:
          - api: NtSetSystemInformation
          - api: ZwSetSystemInformation
