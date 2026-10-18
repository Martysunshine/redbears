<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_susp_service_dir.yml -->
title: Suspicious Service Binary Directory
id: 883faa95-175a-4e22-8181-e5761aeb373c
status: test
description: Detects a service binary running in a suspicious directory
references:
    - https://blog.truesec.com/2021/03/07/exchange-zero-day-proxylogon-and-hafnium/
author: Florian Roth (Nextron Systems)
date: 2021-03-09
modified: 2022-10-09
tags:
    - attack.stealth
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - '\Users\Public\'
            - '\$Recycle.bin'
            - '\Users\All Users\'
            - '\Users\Default\'
            - '\Users\Contacts\'
            - '\Users\Searches\'
            - 'C:\Perflogs\'
            - '\config\systemprofile\'
            - '\Windows\Fonts\'
            - '\Windows\IME\'
            - '\Windows\addins\'
        ParentImage|endswith:
            - '\services.exe'
            - '\svchost.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
