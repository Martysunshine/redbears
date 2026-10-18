<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/process_access/proc_access_win_lsass_powershell_access.yml -->
title: Potential Credential Dumping Attempt Via PowerShell
id: 0f920ebe-7aea-4c54-b202-9aa0c609cfe5
related:
    - id: 3f07b9d1-2082-4c56-9277-613a621983cc
      type: obsolete
    - id: fb656378-f909-47c1-8747-278bf09f4f4f
      type: similar
status: test
description: Detects a PowerShell process requesting access to "lsass.exe", which can be indicative of potential credential dumping attempts
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
author: oscd.community, Natalia Shornikova
date: 2020-10-06
modified: 2023-11-28
tags:
    - attack.credential-access
    - attack.t1003.001
    - detection.threat-hunting
logsource:
    product: windows
    category: process_access
detection:
    selection:
        SourceImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        TargetImage|endswith: '\lsass.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
