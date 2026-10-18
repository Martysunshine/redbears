<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_lsass_werfault_dump.yml -->
title: WerFault LSASS Process Memory Dump
id: c3e76af5-4ce0-4a14-9c9a-25ceb8fda182
status: test
description: Detects WerFault creating a dump file with a name that indicates that the dump file could be an LSASS process memory, which contains user credentials
references:
    - https://github.com/helpsystems/nanodump
author: Florian Roth (Nextron Systems)
date: 2022-06-27
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image: C:\WINDOWS\system32\WerFault.exe
        TargetFilename|contains:
            - '\lsass'
            - 'lsass.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
