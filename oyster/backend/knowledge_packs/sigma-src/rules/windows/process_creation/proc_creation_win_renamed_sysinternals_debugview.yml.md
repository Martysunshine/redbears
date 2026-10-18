<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_renamed_sysinternals_debugview.yml -->
title: Renamed SysInternals DebugView Execution
id: cd764533-2e07-40d6-a718-cfeec7f2da7f
status: test
description: Detects suspicious renamed SysInternals DebugView execution
references:
    - https://www.epicturla.com/blog/sysinturla
author: Florian Roth (Nextron Systems)
date: 2020-05-28
modified: 2023-02-14
tags:
    - attack.resource-development
    - attack.t1588.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Product: 'Sysinternals DebugView'
    filter:
        OriginalFileName: 'Dbgview.exe'
        Image|endswith: '\Dbgview.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
