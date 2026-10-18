<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_get_adgroup.yml -->
title: Active Directory Group Enumeration With Get-AdGroup
id: 8c3a6607-b7dc-4f0d-a646-ef38c00b76ee
status: test
description: Detects usage of the "Get-AdGroup" cmdlet to enumerate Groups within Active Directory
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md
author: frack113
date: 2022-03-17
modified: 2022-11-17
tags:
    - attack.discovery
    - attack.t1069.002
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Get-AdGroup '
            - '-Filter'
    condition: selection
falsepositives:
    - Unknown
level: low
