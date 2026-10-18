<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/packer/kkrunchy/packed-with-kkrunchy.yml -->
rule:
  meta:
    name: packed with kkrunchy
    namespace: anti-analysis/packer/kkrunchy
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
      - http://www.farbrausch.de/~fg/kkrunchy/
      - https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
    examples:
      - f9ac6b16273556b3a57bf2c6d7e7db97
  features:
    - or:
      - section: kkrunchy
