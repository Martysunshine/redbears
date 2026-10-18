<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/packer/nspack/packed-with-nspack.yml -->
rule:
  meta:
    name: packed with nspack
    namespace: anti-analysis/packer/nspack
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
      - 02179f3ba93663074740b5c0d283bae2
  features:
    - or:
      - section: .nsp0
      - section: .nsp1
      - section: .nsp2
