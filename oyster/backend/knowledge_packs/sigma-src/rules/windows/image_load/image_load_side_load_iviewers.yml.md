<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_side_load_iviewers.yml -->
title: Potential Iviewers.DLL Sideloading
id: 4c21b805-4dd7-469f-b47d-7383a8fcb437
status: test
description: Detects potential DLL sideloading of "iviewers.dll" (OLE/COM Object Interface Viewer)
references:
    - https://www.secureworks.com/research/shadowpad-malware-analysis
author: X__Junior (Nextron Systems)
date: 2023-03-21
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.execution
    - attack.stealth
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\iviewers.dll'
    filter:
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\Windows Kits\'
            - 'C:\Program Files\Windows Kits\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
