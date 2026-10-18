<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2023/TA/Diamond-Sleet/file_event_win_apt_diamond_sleet_indicators.yml -->
title: Diamond Sleet APT File Creation Indicators
id: e1212b32-55ff-4dfb-a595-62b572248056
status: test
description: Detects file creation activity that is related to Diamond Sleet APT activity
references:
    - https://www.microsoft.com/en-us/security/blog/2023/10/18/multiple-north-korean-threat-actors-exploiting-the-teamcity-cve-2023-42793-vulnerability/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-10-24
tags:
    - attack.execution
    - detection.emerging-threats
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - ':\ProgramData\4800-84DC-063A6A41C5C'
            - ':\ProgramData\clip.exe'
            - ':\ProgramData\DSROLE.dll'
            - ':\ProgramData\Forest64.exe'
            - ':\ProgramData\readme.md'
            - ':\ProgramData\Version.dll'
            - ':\ProgramData\wsmprovhost.exe'
    condition: selection
falsepositives:
    - Unlikely
level: high
