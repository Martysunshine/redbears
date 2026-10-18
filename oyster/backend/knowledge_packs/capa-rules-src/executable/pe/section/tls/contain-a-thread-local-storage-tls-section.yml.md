<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/executable/pe/section/tls/contain-a-thread-local-storage-tls-section.yml -->
rule:
  meta:
    name: contain a thread local storage (.tls) section
    namespace: executable/pe/section/tls
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: file
      dynamic: file
    examples:
      - Practical Malware Analysis Lab 16-02.exe_
  features:
    - section: .tls
