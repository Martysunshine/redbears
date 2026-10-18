<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/obfuscation/obfuscated-with-spicesdotnet-obfuscator.yml -->
rule:
  meta:
    name: obfuscated with Spices.Net Obfuscator
    namespace: anti-analysis/obfuscation
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Defense Evasion::Obfuscated Files or Information [T1027]
    mbc:
      - Anti-Static Analysis::Executable Code Obfuscation [B0032]
    references:
      - https://www.9rays.net/Category/53-spicesnet-suite.aspx
      - https://github.com/de4dot/de4dot/blob/master/de4dot.code/deobfuscators/Spices_Net/Deobfuscator.cs#L122
    examples:
      - 0953cc3b77ed2974b09e3a00708f88de931d681e2d0cb64afbaf714610beabe6
  features:
    - and:
      - match: compiled to the .NET platform
      - or:
        - string: "NineRays.Obfuscator.Evaluation"
        - string: "NineRays.Obfuscator.SoftwareWatermarkAttribute"
