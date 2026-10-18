<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/os/version/get-linux-distribution.yml -->
rule:
  meta:
    name: get Linux distribution
    namespace: host-interaction/os/version
    authors:
      - joakim@intezer.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::System Information Discovery [T1082]
    examples:
      - 7351f8a40c5450557b24622417fc478d:0x405438
  features:
    - and:
      - os: linux
      - match: host-interaction/file-system/read
      - or:
        - string: "/etc/os-release"
        - string: "/etc/lsb-release"
        - string: "/etc/issue"
