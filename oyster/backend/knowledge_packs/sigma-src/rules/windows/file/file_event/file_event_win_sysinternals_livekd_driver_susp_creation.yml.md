<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_sysinternals_livekd_driver_susp_creation.yml -->
title: LiveKD Driver Creation By Uncommon Process
id: 059c5af9-5131-4d8d-92b2-de4ad6146712
related:
    - id: 16fe46bb-4f64-46aa-817d-ff7bec4a2352
      type: similar
status: test
description: Detects the creation of the LiveKD driver by a process image other than "livekd.exe".
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-16
tags:
    - attack.privilege-escalation
    - attack.stealth
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename: 'C:\Windows\System32\drivers\LiveKdD.SYS'
    filter_main_legit_name:
        Image|endswith:
            - '\livekd.exe'
            - '\livek64.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Administrators might rename LiveKD before its usage which could trigger this. Add additional names you use to the filter
level: high
