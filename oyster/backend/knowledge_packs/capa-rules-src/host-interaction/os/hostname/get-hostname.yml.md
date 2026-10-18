<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/os/hostname/get-hostname.yml -->
rule:
  meta:
    name: get hostname
    namespace: host-interaction/os/hostname
    authors:
      - moritz.raabe@mandiant.com
      - joakim@intezer.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Discovery::System Information Discovery [T1082]
    mbc:
      - Discovery::System Information Discovery [E1082]
    examples:
      - 9324D1A8AE37A36AE560C37448C9705A:0x4052A0
      - 7351f8a40c5450557b24622417fc478d:0x405438
  features:
    - or:
      - api: kernel32.GetComputerName
      - api: kernel32.GetComputerNameEx
      - api: GetComputerObjectName
      - api: ws2_32.gethostname
      - api: gethostname
      - property/read: System.Environment::MachineName
