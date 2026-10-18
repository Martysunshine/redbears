<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_load_by_rundll32.yml -->
title: CobaltStrike Load by Rundll32
id: ae9c6a7c-9521-42a6-915e-5aaa8689d529
status: test
description: Rundll32 can be use by Cobalt Strike with StartW function to load DLLs from the command line.
references:
    - https://www.cobaltstrike.com/help-windows-executable
    - https://redcanary.com/threat-detection-report/
    - https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/
author: Wojciech Lesicki
date: 2021-06-01
modified: 2022-09-16
tags:
    - attack.stealth
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_rundll:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: RUNDLL32.EXE
        - CommandLine|contains:
              - 'rundll32.exe'
              - 'rundll32 '
    selection_params:
        CommandLine|contains: '.dll'
        CommandLine|endswith:
            - ' StartW'
            - ',StartW'
    condition: all of selection*
falsepositives:
    - Unknown
level: high
