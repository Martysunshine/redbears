<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_set/registry_set_persistence_typed_paths.yml -->
title: Potential Persistence Via TypedPaths
id: 086ae989-9ca6-4fe7-895a-759c5544f247
status: test
description: Detects modification addition to the 'TypedPaths' key in the user or admin registry from a non standard application. Which might indicate persistence attempt
references:
    - https://twitter.com/dez_/status/1560101453150257154
    - https://forensafe.com/blogs/typedpaths.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-22
modified: 2023-08-17
tags:
    - attack.persistence
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths\'
    filter:
        Image:
            - 'C:\Windows\explorer.exe'
            - 'C:\Windows\SysWOW64\explorer.exe'
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high
