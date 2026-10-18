<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/obfuscation/obfuscated-with-advobfuscator.yml -->
rule:
  meta:
    name: obfuscated with ADVobfuscator
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
      - https://github.com/andrivet/ADVobfuscator
    examples:
      - c1969efd1e2be79909b880f4dbb8725e52efca82236f8a2165c5a8245393fcd6
  features:
    - substring: "@ADVobfuscator@andrivet@@"
