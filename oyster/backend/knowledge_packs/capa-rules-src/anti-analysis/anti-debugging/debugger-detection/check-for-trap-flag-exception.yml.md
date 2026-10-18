<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-debugging/debugger-detection/check-for-trap-flag-exception.yml -->
rule:
  meta:
    name: check for trap flag exception
    namespace: anti-analysis/anti-debugging/debugger-detection
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: basic block
      dynamic: unsupported  # requires mnemonic features
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection [B0001]
    references:
      - https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/TrapFlag.cpp
    examples:
      - al-khaser_x86.exe_:0x431680
      - al-khaser_x64.exe_:0x140030CB0
  features:
    - and:
      - or:
        - description: read/write EFLAGS register
        - and:
          - mnemonic: pushf
          - mnemonic: popf
        - and:
          - mnemonic: pushfd
          - mnemonic: popfd
        - and:
          - mnemonic: pushfq
          - mnemonic: popfq
      - or:
        - description: set trap flag
        - instruction:
          - mnemonic: or
          - number: 0x100
        - instruction:
          - mnemonic: bts
          - number: 0x8
