<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/packer/gopacker/packed-with-gopacker.yml -->
rule:
  meta:
    name: packed with GoPacker
    namespace: anti-analysis/packer/gopacker
    authors:
      - jared.wilson@mandiant.com
    description: The sample appears to be packed with GoPacker.
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]
    mbc:
      - Anti-Static Analysis::Software Packing::Standard Compression [F0001.002]
    references:
      - https://github.com/nirhaas/gopacker
    examples:
      - 4122acca2f9ea98fc3f3ad040688e4ce
  features:
    - and:
      - string: "main.packedPath"
      - string: "main.unpackedPath"
      - string: "main.footerMagic"
      - optional:
        - string: "path   github.com/nirhaas/gopacker"
        - string: "LALALALA"
          description: LALALALA is the default magic footer; however, it can be changed.
