<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-forensic/timestomp/timestomp-file.yml -->
rule:
  meta:
    name: timestomp file
    namespace: anti-analysis/anti-forensic/timestomp
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Indicator Removal::Timestomp [T1070.006]
    examples:
      - Practical Malware Analysis Lab 03-04.exe_:0x4014e0
  features:
    - and:
      - or:
        - api: kernel32.GetSystemTime
        - api: kernel32.FileTimeToLocalFileTime
        - api: kernel32.GetSystemTimeAsFileTime
        - api: kernel32.SystemTimeToFileTime
        - api: kernel32.GetFileTime
      - api: kernel32.SetFileTime
