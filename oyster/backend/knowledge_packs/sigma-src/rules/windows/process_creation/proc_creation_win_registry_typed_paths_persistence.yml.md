<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_registry_typed_paths_persistence.yml -->
title: Persistence Via TypedPaths - CommandLine
id: ec88289a-7e1a-4cc3-8d18-bd1f60e4b9ba
status: test
description: Detects modification addition to the 'TypedPaths' key in the user or admin registry via the commandline. Which might indicate persistence attempt
references:
    - https://twitter.com/dez_/status/1560101453150257154
    - https://forensafe.com/blogs/typedpaths.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-22
tags:
    - attack.persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
    condition: selection
falsepositives:
    - Unknown
level: medium
