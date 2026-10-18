<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/obfuscation/obfuscated-with-dotfuscator.yml -->
rule:
  meta:
    name: obfuscated with Dotfuscator
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
      - https://www.preemptive.com/products/dotfuscator/
    examples:
      - 2dae11cc5f86f5399b560b8837c26274b7e09431deed669b0844fef44e917915
  features:
    - and:
      - match: compiled to the .NET platform
      - string: "DotfuscatorAttribute"
