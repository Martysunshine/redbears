<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/packer/dxpack/packed-with-dxpack.yml -->
rule:
  meta:
    name: packed with DXPack
    namespace: anti-analysis/packer/dxpack
    authors:
      - jakubjozwiak@google.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]
    references:
      - https://web.archive.org/web/20161023220842/http://coder.pub/2014/10/pe-file-packer-step-by-step-step-12-bugfixes/
    examples:
      - acd2d663799e8919b09e188adbb55ac655e5409bcd073e6a4b6576163e6e65d5
  features:
    - or:
      - section: kaimi.ru
      - section: coderpub
