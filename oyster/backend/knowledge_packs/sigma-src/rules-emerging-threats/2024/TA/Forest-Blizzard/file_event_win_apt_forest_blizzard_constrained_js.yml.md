<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2024/TA/Forest-Blizzard/file_event_win_apt_forest_blizzard_constrained_js.yml -->
title: Forest Blizzard APT - JavaScript Constrained File Creation
id: ec7c4e9b-9bc9-47c7-a32f-b53b598da642
status: test
description: |
    Detects the creation of JavaScript files inside of the DriverStore directory.
    Forest Blizzard used this to exploit the CVE-2022-38028 vulnerability in Windows Print Spooler service by modifying a JavaScript constraints file and executing it with SYSTEM-level permissions.
references:
    - https://www.microsoft.com/en-us/security/blog/2024/04/22/analyzing-forest-blizzards-custom-post-compromise-tool-for-exploiting-cve-2022-38028-to-obtain-credentials/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-04-23
tags:
    - attack.defense-impairment
    - attack.t1685.001
    - detection.emerging-threats
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\Windows\System32\DriverStore\FileRepository\'
        TargetFilename|endswith: '\.js'
    condition: selection
falsepositives:
    - Unlikely
level: medium
