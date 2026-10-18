<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/hardware/cpu/get-number-of-processor-cores.yml -->
rule:
  meta:
    name: get number of processor cores
    namespace: host-interaction/hardware/cpu
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::System Information Discovery [T1082]
    references:
      - https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Generic.cpp#L207
    examples:
      - al-khaser_x86.exe_:0x435BA0
  features:
    - and:
      - string: /SELECT\s+\*\s+FROM\s+Win32_Processor/
      - string: "NumberOfCores"
