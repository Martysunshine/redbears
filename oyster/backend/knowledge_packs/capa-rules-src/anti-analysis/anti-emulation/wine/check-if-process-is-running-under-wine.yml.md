<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-emulation/wine/check-if-process-is-running-under-wine.yml -->
rule:
  meta:
    name: check if process is running under wine
    namespace: anti-analysis/anti-emulation/wine
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]
    mbc:
      - Anti-Behavioral Analysis::Emulator Detection [B0004]
    references:
      - https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Wine.cpp
    examples:
      - ccbf7cba35bab56563c0fbe4237fdc41:0x40d750
  features:
    - or:
      - string: /SOFTWARE\\Wine/i
      - and:
        - api: GetModuleHandle
        - api: GetProcAddress
        - string: "wine_get_unix_file_name"
        - or:
          - string: "kernel32.dll"
          - string: "ntdll.dll"
