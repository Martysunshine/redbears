<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_dinjector.yml -->
title: HackTool - DInjector PowerShell Cradle Execution
id: d78b5d61-187d-44b6-bf02-93486a80de5a
status: test
description: Detects the use of the Dinject PowerShell cradle based on the specific flags
references:
    - https://web.archive.org/web/20211001064856/https://github.com/snovvcrash/DInjector # Original got deleted. This is a fork
author: Florian Roth (Nextron Systems)
date: 2021-12-07
modified: 2023-02-04
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' /am51'
            - ' /password'
    condition: selection
falsepositives:
    - Unlikely
level: critical
