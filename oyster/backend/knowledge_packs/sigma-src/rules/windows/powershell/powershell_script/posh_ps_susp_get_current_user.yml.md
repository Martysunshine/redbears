<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_susp_get_current_user.yml -->
title: Suspicious PowerShell Get Current User
id: 4096a49c-7de4-4da0-a230-c66ccd56ea5a
status: test
description: Detects the use of PowerShell to identify the current logged user.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1033/T1033.md#atomic-test-4---user-discovery-with-env-vars-powershell-script
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1033/T1033.md#atomic-test-5---getcurrent-user-with-powershell-script
author: frack113
date: 2022-04-04
tags:
    - attack.discovery
    - attack.t1033
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains:
            - '[System.Environment]::UserName'
            - '$env:UserName'
            - '[System.Security.Principal.WindowsIdentity]::GetCurrent()'
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: low
