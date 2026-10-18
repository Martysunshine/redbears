<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_safetykatz.yml -->
title: HackTool - SafetyKatz Execution
id: b1876533-4ed5-4a83-90f3-b8645840a413
status: test
description: Detects the execution of the hacktool SafetyKatz via PE information and default Image name
references:
    - https://github.com/GhostPack/SafetyKatz
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-20
modified: 2023-02-04
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\SafetyKatz.exe'
        - OriginalFileName: 'SafetyKatz.exe'
        - Description: 'SafetyKatz'
    condition: selection
falsepositives:
    - Unlikely
level: critical
