<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-debugging/debugger-detection/check-for-kernel-debugger-via-shared-user-data-structure.yml -->
rule:
  meta:
    name: check for kernel debugger via shared user data structure
    namespace: anti-analysis/anti-debugging/debugger-detection
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: unsupported  # requires mnemonic features
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection [B0001]
    references:
      - https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/SharedUserData_KernelDebugger.cpp
      - http://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/kuser_shared_data.htm
    examples:
      - al-khaser_x86.exe_:0x430E60
  features:
    - and:
      - number: 0x7FFE02D4 = UserSharedData->KdDebuggerEnabled
      - instruction:
        - mnemonic: and
        - number: 0x2 = KdDebuggerNotPresent
      - instruction:
        - mnemonic: and
        - number: 0x1 = KdDebuggerEnabled
