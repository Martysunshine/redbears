<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_tsclient_filewrite_startup.yml -->
title: Hijack Legit RDP Session to Move Laterally
id: 52753ea4-b3a0-4365-910d-36cff487b789
status: test
description: Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder
author: Samir Bousseaden
references:
    - Internal Research
date: 2019-02-21
modified: 2021-11-27
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image|endswith: '\mstsc.exe'
        TargetFilename|contains: '\Microsoft\Windows\Start Menu\Programs\Startup\'
    condition: selection
falsepositives:
    - Unlikely
level: high
