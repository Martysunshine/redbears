<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-debugging/debugger-detection/check-for-outputdebugstring-error.yml -->
rule:
  meta:
    name: check for OutputDebugString error
    namespace: anti-analysis/anti-debugging/debugger-detection
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: basic block
      dynamic: span of calls
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection::OutputDebugString [B0001.016]
    examples:
      - Practical Malware Analysis Lab 16-02.exe_:0x401020
  features:
    - and:
      - api: kernel32.SetLastError
      - api: kernel32.GetLastError
      - api: kernel32.OutputDebugString
