<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2023/TA/Onyx-Sleet/file_event_win_apt_onyx_sleet_indicators.yml -->
title: Onyx Sleet APT File Creation Indicators
id: 2fef4fd9-7206-40d1-b4f5-ad6441d0cd9b
status: test
description: Detects file creation activity that is related to Onyx Sleet APT activity
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
        TargetFilename|endswith: ':\Windows\ADFS\bg\inetmgr.exe'
    condition: selection
falsepositives:
    - Unlikely
level: high
