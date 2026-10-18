<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/windows-file-protection/bypass-windows-file-protection.yml -->
rule:
  meta:
    name: bypass Windows File Protection
    namespace: host-interaction/file-system/windows-file-protection
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Defense Evasion::Disable or Evade Security Tools::Bypass Windows File Protection [F0004.007]
    examples:
      - Practical Malware Analysis Lab 01-04.exe_:0x401174
  features:
    - and:
      - string: "sfc_os.dll"
        description: System File Checker
      - number: 0x2 = SfcTerminateWatcherThread
      - match: link function at runtime on Windows
