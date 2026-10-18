<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/driver/interact-with-driver-via-ioctl.yml -->
rule:
  meta:
    name: interact with driver via IOCTL
    namespace: host-interaction/driver
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: instruction
      dynamic: call
    examples:
      - Practical Malware Analysis Lab 10-03.exe_:0x40108c
  features:
    - or:
      - api: DeviceIoControl
