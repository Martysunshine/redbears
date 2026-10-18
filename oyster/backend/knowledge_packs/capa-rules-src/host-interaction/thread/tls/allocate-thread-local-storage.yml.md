<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/thread/tls/allocate-thread-local-storage.yml -->
rule:
  meta:
    name: allocate thread local storage
    namespace: host-interaction/thread/tls
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - Process::Allocate Thread Local Storage [C0040]
    examples:
      - 03B236B23B1EC37C663527C1F53AF3FE:0x18000ADF6
  features:
    - or:
      - api: kernel32.TlsAlloc
