<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_sysinternals_livekd_execution.yml -->
title: Potential Memory Dumping Activity Via LiveKD
id: a85f7765-698a-4088-afa0-ecfbf8d01fa4
status: test
description: Detects execution of LiveKD based on PE metadata or image name
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/livekd
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-15
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - '\livekd.exe'
              - '\livekd64.exe'
        - OriginalFileName: 'livekd.exe'
    condition: selection
falsepositives:
    - Administration and debugging activity (must be investigated)
level: medium
