<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_susp_dumpstack_log_evasion.yml -->
title: DumpStack.log Defender Evasion
id: 4f647cfa-b598-4e12-ad69-c68dd16caef8
status: test
description: Detects the use of the filename DumpStack.log to evade Microsoft Defender
references:
    - https://twitter.com/mrd0x/status/1479094189048713219
author: Florian Roth (Nextron Systems)
date: 2022-01-06
modified: 2022-06-17
tags:
    - attack.defense-impairment
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\DumpStack.log'
    selection_download:
        CommandLine|contains: ' -o DumpStack.log'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: critical
