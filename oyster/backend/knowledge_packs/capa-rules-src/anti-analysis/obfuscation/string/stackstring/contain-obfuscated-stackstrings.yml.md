<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/obfuscation/string/stackstring/contain-obfuscated-stackstrings.yml -->
rule:
  meta:
    name: contain obfuscated stackstrings
    namespace: anti-analysis/obfuscation/string/stackstring
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: basic block
      dynamic: unsupported
    att&ck:
      - Defense Evasion::Obfuscated Files or Information::Indicator Removal from Tools [T1027.005]
    mbc:
      - Anti-Static Analysis::Executable Code Obfuscation::Argument Obfuscation [B0032.020]
      - Anti-Static Analysis::Executable Code Obfuscation::Stack Strings [B0032.017]
    examples:
      - Practical Malware Analysis Lab 16-03.exe_:0x4013D0
  features:
    - characteristic: stack string
