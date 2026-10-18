<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-debugging/debugger-detection/execute-anti-debugging-instructions.yml -->
rule:
  meta:
    name: execute anti-debugging instructions
    namespace: anti-analysis/anti-debugging/debugger-detection
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: unsupported  # requires mnemonic features
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection::Anti-debugging Instructions [B0001.034]
    examples:
      - Practical Malware Analysis Lab 16-03.exe_:0x401300
  features:
    - or:
      - count(mnemonic(rdtsc)): 2 or more
      - mnemonic: icebp
