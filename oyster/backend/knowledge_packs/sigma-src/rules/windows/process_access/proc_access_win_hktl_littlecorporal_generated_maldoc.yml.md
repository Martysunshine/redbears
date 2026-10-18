<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_access/proc_access_win_hktl_littlecorporal_generated_maldoc.yml -->
title: HackTool - LittleCorporal Generated Maldoc Injection
id: 7bdde3bf-2a42-4c39-aa31-a92b3e17afac
status: test
description: Detects the process injection of a LittleCorporal generated Maldoc.
references:
    - https://github.com/connormcgarr/LittleCorporal
author: Christian Burkard (Nextron Systems)
date: 2021-08-09
modified: 2023-11-28
tags:
    - attack.execution
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1204.002
    - attack.t1055.003
logsource:
    category: process_access
    product: windows
detection:
    selection:
        SourceImage|endswith: '\winword.exe'
        CallTrace|contains|all:
            - ':\Windows\Microsoft.NET\Framework64\v2.'
            - 'UNKNOWN'
    condition: selection
falsepositives:
    - Unknown
level: high
