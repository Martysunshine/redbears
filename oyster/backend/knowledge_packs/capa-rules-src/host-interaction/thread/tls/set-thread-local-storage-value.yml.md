<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/thread/tls/set-thread-local-storage-value.yml -->
rule:
  meta:
    name: set thread local storage value
    namespace: host-interaction/thread/tls
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Process::Set Thread Local Storage Value [C0041]
    examples:
      - 03B236B23B1EC37C663527C1F53AF3FE:0x18000AE21
  features:
    - and:
      - api: kernel32.TlsSetValue
      - optional:
        - match: allocate thread local storage
