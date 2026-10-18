<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/recycle-bin/empty-recycle-bin-quietly.yml -->
rule:
  meta:
    name: empty recycle bin quietly
    namespace: host-interaction/recycle-bin
    authors:
      - matthew.williams@mandiant.com
    scopes:
      static: basic block
      dynamic: unsupported  # requires offset, mnemonic features
    att&ck:
      - Defense Evasion::Indicator Removal [T1070]
    references:
      - https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shemptyrecyclebina
    examples:
      - 276F691A3DF25481F59D79781799E35F:0x1400254E0
  features:
    - and:
      - api: SHEmptyRecycleBin
      - instruction:
        - or:
          - and:
            - mnemonic: cmp
            - number: 7 = SHERB_NOSOUND|SHERB_NOPROGRESSUI|SHERB_NOCONFIRMATION
          - and:
            - mnemonic: lea
            - offset: 7 = SHERB_NOSOUND|SHERB_NOPROGRESSUI|SHERB_NOCONFIRMATION
