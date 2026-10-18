<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/anti-analysis/anti-forensic/disable-powershell-transcription.yml -->
rule:
  meta:
    name: disable PowerShell transcription
    namespace: anti-analysis/anti-forensic
    authors:
      - jakubjozwiak@google.com
    description: Match on files capable of patching the FlushContentToDisk method in order to prevent PowerShell from writing transcripts to disk.
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Impair Defenses::Disable or Modify Tools [T1562.001]
    mbc:
      - Defense Evasion::Disable or Evade Security Tools [F0004]
    references:
      - https://itm4n.github.io/reinventing-powershell/
    examples:
      - 7cd03db8ed91a66920cc03026baa2df2a8370293b072218b9fbf6d9a21cad66b:0x180004EB0
  features:
    - and:
      - match: change memory protection
      - string: "System.Management.Automation.Host.TranscriptionOption"
      - string: "FlushContentToDisk"
      - optional:
        - number: 0xc3 = RET
