<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-parallels.yml -->
rule:
  meta:
    name: reference anti-VM strings targeting Parallels
    namespace: anti-analysis/anti-vm/vm-detection
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]
    mbc:
      - Anti-Behavioral Analysis::Virtual Machine Detection [B0009]
    references:
      - https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Parallels.cpp
    examples:
      - al-khaser_x86.exe_
  features:
    - or:
      - string: /Parallels/i
      - string: /prl_cc\.exe/i
      - string: /prl_tools\.exe/i
      - string: /prl hyperv/i
