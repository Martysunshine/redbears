<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_rundll32_shelldispatch_potential_abuse.yml -->
title: Potential ShellDispatch.DLL Functionality Abuse
id: 82343930-652f-43f5-ab70-2ee9fdd6d5e9
status: test
description: Detects potential "ShellDispatch.dll" functionality abuse to execute arbitrary binaries via "ShellExecute"
references:
    - https://www.hexacorn.com/blog/2023/06/07/this-lolbin-doesnt-exist/
author: X__Junior (Nextron Systems)
date: 2023-06-20
tags:
    - attack.execution
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
    selection_cli:
        CommandLine|contains: 'RunDll_ShellExecuteW'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: medium
