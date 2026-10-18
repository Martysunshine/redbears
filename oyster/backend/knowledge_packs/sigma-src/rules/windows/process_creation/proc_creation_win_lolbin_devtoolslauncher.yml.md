<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_lolbin_devtoolslauncher.yml -->
title: Devtoolslauncher.exe Executes Specified Binary
id: cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6
status: test
description: The Devtoolslauncher.exe executes other binary
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Devtoolslauncher/
    - https://twitter.com/_felamos/status/1179811992841797632
author: Beyu Denis, oscd.community (rule), @_felamos (idea)
date: 2019-10-12
modified: 2021-11-27
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\devtoolslauncher.exe'
        CommandLine|contains: 'LaunchForDeploy'
    condition: selection
falsepositives:
    - Legitimate use of devtoolslauncher.exe by legitimate user
level: high
