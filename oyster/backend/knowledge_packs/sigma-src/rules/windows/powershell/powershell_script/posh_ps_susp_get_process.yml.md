<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_susp_get_process.yml -->
title: Suspicious Process Discovery With Get-Process
id: af4c87ce-bdda-4215-b998-15220772e993
status: test
description: Get the processes that are running on the local computer.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1057/T1057.md#atomic-test-3---process-discovery---get-process
    - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.4
author: frack113
date: 2022-03-17
tags:
    - attack.discovery
    - attack.t1057
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: Get-Process
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: low
