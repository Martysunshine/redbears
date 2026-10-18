<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_cscript_wscript_dropper.yml -->
title: WScript or CScript Dropper - File
id: 002bdb95-0cf1-46a6-9e08-d38c128a6127
related:
    - id: cea72823-df4d-4567-950c-0b579eaf0846
      type: derived
status: test
description: Detects a file ending in jse, vbe, js, vba, vbs, wsf, wsh written by cscript.exe or wscript.exe
references:
    - WScript or CScript Dropper (cea72823-df4d-4567-950c-0b579eaf0846)
author: Tim Shelton
date: 2022-01-10
modified: 2026-02-17
tags:
    - attack.execution
    - attack.t1059.005
    - attack.t1059.007
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
        TargetFilename|contains:
            - ':\Perflogs\'
            - ':\ProgramData\'
            - ':\Temp\'
            - ':\Tmp\'
            - ':\Users\'
            - ':\Windows\Temp\'
            - '\AppData\Local\Temp'
            - '\AppData\Roaming\Temp'
            - '\Start Menu\Programs\Startup\'
            - '\Temporary Internet'
        TargetFilename|endswith:
            - '.js'
            - '.jse'
            - '.vba'
            - '.vbe'
            - '.vbs'
            - '.wsf'
            - '.wsh'
    condition: selection
falsepositives:
    - Unknown
level: high
