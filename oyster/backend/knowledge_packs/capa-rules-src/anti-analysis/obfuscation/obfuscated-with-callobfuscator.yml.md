<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/obfuscation/obfuscated-with-callobfuscator.yml -->
rule:
  meta:
    name: obfuscated with callobfuscator
    namespace: anti-analysis/obfuscation
    authors:
      - johnk3r
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Defense Evasion::Obfuscated Files or Information [T1027]
    mbc:
      - Anti-Static Analysis::Executable Code Obfuscation [B0032]
    examples:
      - 71A4F9B800D81FF6632B9892A6A502C412C141341E46D697A8C004E2F460913B
  features:
    - section: .cobf
