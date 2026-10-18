<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_lolbin_vsiisexelauncher.yml -->
title: Use of VSIISExeLauncher.exe
id: 18749301-f1c5-4efc-a4c3-276ff1f5b6f8
status: test
description: The "VSIISExeLauncher.exe" binary part of the Visual Studio/VS Code can be used to execute arbitrary binaries
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/VSIISExeLauncher/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-09
tags:
    - attack.execution
    - attack.stealth
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\VSIISExeLauncher.exe'
        - OriginalFileName: 'VSIISExeLauncher.exe'
    selection_cli:
        CommandLine|contains:
            - ' -p '
            - ' -a '
    condition: all of selection*
falsepositives:
    - Unknown
level: medium
