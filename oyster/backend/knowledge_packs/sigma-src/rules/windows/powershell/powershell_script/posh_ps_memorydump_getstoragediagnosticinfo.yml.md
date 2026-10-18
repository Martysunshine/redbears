<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_memorydump_getstoragediagnosticinfo.yml -->
title: Live Memory Dump Using Powershell
id: cd185561-4760-45d6-a63e-a51325112cae
status: test
description: Detects usage of a PowerShell command to dump the live memory of a Windows machine
references:
    - https://learn.microsoft.com/en-us/powershell/module/storage/get-storagediagnosticinfo?view=windowsserver2022-ps
author: Max Altgelt (Nextron Systems)
date: 2021-09-21
modified: 2022-12-25
tags:
    - attack.credential-access
    - attack.t1003
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Get-StorageDiagnosticInfo'
            - '-IncludeLiveDump'
    condition: selection
falsepositives:
    - Diagnostics
level: high
