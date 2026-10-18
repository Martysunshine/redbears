<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_powershell_obfuscation_via_utf8.yml -->
title: Potential PowerShell Obfuscation Via WCHAR/CHAR
id: e312efd0-35a1-407f-8439-b8d434b438a6
status: test
description: Detects suspicious encoded character syntax often used for defense evasion
references:
    - https://twitter.com/0gtweet/status/1281103918693482496
author: Florian Roth (Nextron Systems)
date: 2020-07-09
modified: 2025-03-03
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.001
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '[char]0x'
            - '(WCHAR)0x'
    condition: selection
falsepositives:
    - Unknown
level: high
