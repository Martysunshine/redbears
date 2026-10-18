<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_renamed_rurat.yml -->
title: Renamed Remote Utilities RAT (RURAT) Execution
id: 9ef27c24-4903-4192-881a-3adde7ff92a5
status: test
description: Detects execution of renamed Remote Utilities (RURAT) via Product PE header field
references:
    - https://redcanary.com/blog/misbehaving-rats/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-19
modified: 2023-02-03
tags:
    - attack.collection
    - attack.command-and-control
    - attack.discovery
    - attack.stealth
    - attack.s0592
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Product: 'Remote Utilities'
    filter:
        Image|endswith:
            - '\rutserv.exe'
            - '\rfusclient.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
