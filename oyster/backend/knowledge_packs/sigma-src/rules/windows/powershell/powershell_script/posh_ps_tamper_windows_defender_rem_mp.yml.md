<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_rem_mp.yml -->
title: Tamper Windows Defender Remove-MpPreference - ScriptBlockLogging
id: ae2bdd58-0681-48ac-be7f-58ab4e593458
related:
    - id: 07e3cb2c-0608-410d-be4b-1511cb1a0448
      type: similar
status: test
description: Detects attempts to remove Windows Defender configuration using the 'MpPreference' cmdlet
references:
    - https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/windows-10-controlled-folder-access-event-search/ba-p/2326088
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-05
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_remove:
        ScriptBlockText|contains: 'Remove-MpPreference'
    selection_tamper:
        ScriptBlockText|contains:
            - '-ControlledFolderAccessProtectedFolders '
            - '-AttackSurfaceReductionRules_Ids '
            - '-AttackSurfaceReductionRules_Actions '
            - '-CheckForSignaturesBeforeRunningScan '
    condition: all of selection_*
falsepositives:
    - Legitimate PowerShell scripts
level: high
