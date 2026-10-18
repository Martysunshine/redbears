<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_psattack.yml -->
title: PowerShell PSAttack
id: b7ec41a4-042c-4f31-a5db-d0fcde9fa5c5
status: test
description: Detects the use of PSAttack PowerShell hack tool
references:
    - https://adsecurity.org/?p=2921
author: Sean Metcalf (source), Florian Roth (Nextron Systems)
date: 2017-03-05
modified: 2022-12-25
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: 'PS ATTACK!!!'
    condition: selection
falsepositives:
    - Unknown
level: high
