<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/packer/pespin/packed-with-pespin.yml -->
rule:
  meta:
    name: packed with PESpin
    namespace: anti-analysis/packer/pespin
    authors:
      - jakub.jozwiak@mandiant.com
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
      - 23e19068ecba68d4396bc097e0278b8eca7e7dcaa4978e34d683231ad2219ae3
      - 4b796a64abe7675254cd6f8a6c9b83949673158840a4a04c36e7c9068ec14cc8
  features:
    - or:
      - section: .taz
      - section: .x64
