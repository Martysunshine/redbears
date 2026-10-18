<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/obfuscation/obfuscated-with-deepsea-obfuscator.yml -->
rule:
  meta:
    name: obfuscated with DeepSea Obfuscator
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
      - https://marketplace.visualstudio.com/items?itemName=DeepSeaObfuscator.DeepSeaObfuscator
    examples:
      - 354a5de061795f8d961aae8e668ba9968083b1af09eeb9caed0111e7503974b5
  features:
    - and:
      - match: compiled to the .NET platform
      - string: "DeepSeaObfuscator"
