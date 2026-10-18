<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_remote_access_tools_rurat_non_default_location.yml -->
title: Remote Access Tool - RURAT Execution From Unusual Location
id: e01fa958-6893-41d4-ae03-182477c5e77d
status: test
description: Detects execution of Remote Utilities RAT (RURAT) from an unusual location (outside of 'C:\Program Files')
references:
    - https://redcanary.com/blog/misbehaving-rats/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-19
modified: 2023-03-05
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - '\rutserv.exe'
              - '\rfusclient.exe'
        - Product: 'Remote Utilities'
    filter:
        Image|startswith:
            - 'C:\Program Files\Remote Utilities'
            - 'C:\Program Files (x86)\Remote Utilities'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
