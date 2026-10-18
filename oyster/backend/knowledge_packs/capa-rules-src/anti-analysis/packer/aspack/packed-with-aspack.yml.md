<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/packer/aspack/packed-with-aspack.yml -->
rule:
  meta:
    name: packed with ASPack
    namespace: anti-analysis/packer/aspack
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]
    mbc:
      - Anti-Static Analysis::Software Packing [F0001]
    references:
      - http://www.aspack.com/
      - https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
    examples:
      - 2055994ff75b4309eee3a49c5749d306
  features:
    - or:
      - section: .aspack
      - section: .adata
      - section: .ASPack
      - section: ASPack
      - string: "The procedure entry point %s could not be located in the dynamic link library %s"
      - string: "The ordinal %u could not be located in the dynamic link library %s"
