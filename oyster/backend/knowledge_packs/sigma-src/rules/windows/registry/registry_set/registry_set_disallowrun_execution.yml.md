<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_set/registry_set_disallowrun_execution.yml -->
title: Add DisallowRun Execution to Registry
id: 275641a5-a492-45e2-a817-7c81e9d9d3e9
status: test
description: Detect set DisallowRun to 1 to prevent user running specific computer program
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1112/T1112.md
author: frack113
date: 2022-08-19
modified: 2023-08-17
tags:
    - attack.persistence
    - attack.defense-impairment
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'
        Details: 'DWORD (0x00000001)'
    condition: selection
falsepositives:
    - Unknown
level: medium
