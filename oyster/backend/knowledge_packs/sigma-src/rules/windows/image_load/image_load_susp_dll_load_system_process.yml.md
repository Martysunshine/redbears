<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_susp_dll_load_system_process.yml -->
title: DLL Load By System Process From Suspicious Locations
id: 9e9a9002-56c4-40fd-9eff-e4b09bfa5f6c
status: test
description: Detects when a system process (i.e. located in system32, syswow64, etc.) loads a DLL from a suspicious location or a location with permissive permissions such as "C:\Users\Public"
references:
    - https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC (Idea)
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-17
modified: 2023-09-18
tags:
    - attack.stealth
    - attack.t1070
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Image|startswith: 'C:\Windows\'
        ImageLoaded|startswith:
            # TODO: Add more suspicious paths as you see fit in your env
            - 'C:\Users\Public\'
            - 'C:\PerfLogs\'
    condition: selection
falsepositives:
    - Unknown
level: medium
