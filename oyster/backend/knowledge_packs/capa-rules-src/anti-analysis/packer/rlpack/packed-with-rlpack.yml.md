<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/packer/rlpack/packed-with-rlpack.yml -->
rule:
  meta:
    name: packed with rlpack
    namespace: anti-analysis/packer/rlpack
    authors:
      - "@_re_fox"
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]
    mbc:
      - Anti-Static Analysis::Software Packing [F0001]
    references:
      - https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
    examples:
      - 068a76d4823419b376d418cf03215d5c
  features:
    - or:
      - section: .RLPack
      - section: .packed
