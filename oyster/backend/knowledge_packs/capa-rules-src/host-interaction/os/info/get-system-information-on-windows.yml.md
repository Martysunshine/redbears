<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/os/info/get-system-information-on-windows.yml -->
rule:
  meta:
    name: get system information on Windows
    namespace: host-interaction/os/info
    authors:
      - moritz.raabe@mandiant.com
      - joakim@intezer.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::System Information Discovery [T1082]
    examples:
      - 563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299:0x140002280
  features:
    - and:
      - os: windows
      - or:
        - api: kernel32.GetSystemInfo
        - api: kernel32.GetNativeSystemInfo
        - api: NtQuerySystemInformation
        - api: NtQuerySystemInformationEx
        - api: ntdll.RtlGetNativeSystemInformation
        - api: ZwQuerySystemInformation
        - api: ZwQuerySystemInformationEx
