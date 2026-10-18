<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-debugging/debugger-detection/check-for-time-delay-via-gettickcount.yml -->
rule:
  meta:
    name: check for time delay via GetTickCount
    namespace: anti-analysis/anti-debugging/debugger-detection
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: unsupported  # requires mnemonic features
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection::Timing/Delay Check GetTickCount [B0001.032]
    examples:
      - Practical Malware Analysis Lab 16-03.exe_:0x4013d0
  features:
    - and:
      - count(api(kernel32.GetTickCount)): 2 or more
      - basic block:
        - and:
          - mnemonic: sub
          - mnemonic: cmp
