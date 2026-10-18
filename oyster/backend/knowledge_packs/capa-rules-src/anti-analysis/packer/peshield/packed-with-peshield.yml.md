<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/packer/peshield/packed-with-peshield.yml -->
rule:
  meta:
    name: packed with peshield
    namespace: anti-analysis/packer/peshield
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
      - a3c0a2425ea84103adde03a92176424c
  features:
    - or:
      - section: PESHiELD
      - section: PESHiELD_1
      - string: / PE-SHiELD v[0-9]\.[0-9]/
