<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_lolbin_pubprn.yml -->
title: Pubprn.vbs Proxy Execution
id: 1fb76ab8-fa60-4b01-bddd-71e89bf555da
status: test
description: Detects the use of the 'Pubprn.vbs' Microsoft signed script to execute commands.
references:
    - https://lolbas-project.github.io/lolbas/Scripts/Pubprn/
author: frack113
date: 2022-05-28
tags:
    - attack.stealth
    - attack.t1216.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\pubprn.vbs'
            - 'script:'
    condition: selection
falsepositives:
    - Unknown
level: medium
