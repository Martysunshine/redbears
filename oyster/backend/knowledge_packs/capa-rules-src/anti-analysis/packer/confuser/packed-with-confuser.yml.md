<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/packer/confuser/packed-with-confuser.yml -->
rule:
  meta:
    name: packed with Confuser
    namespace: anti-analysis/packer/confuser
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: file
      dynamic: unsupported  # requires class features
    att&ck:
      - Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]
    mbc:
      - Anti-Static Analysis::Software Packing::Confuser [F0001.009]
    examples:
      - b9f5bd514485fb06da39beff051b9fdc
  features:
    - or:
      - class: "ConfusedByAttribute"
