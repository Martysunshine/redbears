<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/hardware/cpu/get-cpu-information.yml -->
rule:
  meta:
    name: get CPU information
    namespace: host-interaction/hardware/cpu
    authors:
      - moritz.raabe@mandiant.com
      - joakim@intezer.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::System Information Discovery [T1082]
    examples:
      - BFB9B5391A13D0AFD787E87AB90F14F5:0x13145B5A
  features:
    - or:
      - and:
        - os: windows
        - match: query or enumerate registry value
        - string: /Hardware\\Description\\System\\CentralProcessor/i
      - and:
        - os: linux
        - match: host-interaction/file-system/read
        - string: "/proc/cpuinfo"
      - and:
        - os: linux
        - api: system
        - substring: "/proc/cpuinfo"
