<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/packer/pecompact/packed-with-pecompact.yml -->
rule:
  meta:
    name: packed with PECompact
    namespace: anti-analysis/packer/pecompact
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
      - https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
    examples:
      - Practical Malware Analysis Lab 18-03.exe_
  features:
    - or:
      - section: PEC2TO
      - section: PEC2
      - section: pec
      - section: pec1
      - section: pec2
      - section: pec3
      - section: pec4
      - section: pec5
      - section: pec6
      - section: PEC2MO
