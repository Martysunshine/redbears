<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_set/registry_set_susp_reg_persist_explorer_run.yml -->
title: Registry Persistence via Explorer Run Key
id: b7916c2a-fa2f-4795-9477-32b731f70f11
status: test
description: Detects a possible persistence mechanism using RUN key for Windows Explorer and pointing to a suspicious folder
references:
    - https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/
author: Florian Roth (Nextron Systems), oscd.community
date: 2018-07-18
modified: 2023-12-11
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        Details|contains:
            - ':\$Recycle.bin\'
            - ':\ProgramData\'
            - ':\Temp\'
            - ':\Users\Default\'
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - '\AppData\Local\Temp\'
    condition: selection
falsepositives:
    - Unknown
level: high
