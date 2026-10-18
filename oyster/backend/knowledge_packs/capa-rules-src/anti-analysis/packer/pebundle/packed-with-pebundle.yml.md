<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/packer/pebundle/packed-with-pebundle.yml -->
rule:
  meta:
    name: packed with pebundle
    namespace: anti-analysis/packer/pebundle
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
      - db9fe790b4e18abf55df31aa0b81e558
  features:
    - or:
      - section: pebundle
      - section: PEBundle
