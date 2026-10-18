<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_susp_get_gpo.yml -->
title: Suspicious GPO Discovery With Get-GPO
id: eb2fd349-ec67-4caa-9143-d79c7fb34441
status: test
description: Detect use of Get-GPO to get one GPO or all the GPOs in a domain.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1615/T1615.md
    - https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpo?view=windowsserver2022-ps
author: frack113
date: 2022-06-04
tags:
    - attack.discovery
    - attack.t1615
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: Get-GPO
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: low
