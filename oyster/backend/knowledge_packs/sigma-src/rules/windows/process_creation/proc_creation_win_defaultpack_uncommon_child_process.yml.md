<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_defaultpack_uncommon_child_process.yml -->
title: Uncommon Child Process Of Defaultpack.EXE
id: b2309017-4235-44fe-b5af-b15363011957
status: test
description: Detects uncommon child processes of "DefaultPack.EXE" binary as a proxy to launch other programs
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/DefaultPack/
    - https://www.echotrail.io/insights/search/defaultpack.exe
author: frack113
date: 2022-12-31
modified: 2024-04-22
tags:
    - attack.stealth
    - attack.t1218
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\DefaultPack.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
