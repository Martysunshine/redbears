<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-debugging/debugger-detection/check-for-time-delay-via-queryperformancecounter.yml -->
rule:
  meta:
    name: check for time delay via QueryPerformanceCounter
    namespace: anti-analysis/anti-debugging/debugger-detection
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection::Timing/Delay Check QueryPerformanceCounter [B0001.033]
    examples:
      - Practical Malware Analysis Lab 16-03.exe_:0x4011e0
  features:
    - and:
      - count(api(kernel32.QueryPerformanceCounter)): 2 or more
