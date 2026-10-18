<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_wmiprvse_wbemcomn_dll_hijack.yml -->
title: Wmiprvse Wbemcomn DLL Hijack - File
id: 614a7e17-5643-4d89-b6fe-f9df1a79641c
status: test
description: Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network and loading it for a WMI DLL Hijack scenario.
references:
    - https://threathunterplaybook.com/hunts/windows/201009-RemoteWMIWbemcomnDLLHijack/notebook.html
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-10-12
modified: 2022-12-02
tags:
    - attack.execution
    - attack.t1047
    - attack.lateral-movement
    - attack.t1021.002
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image: System
        TargetFilename|endswith: '\wbem\wbemcomn.dll'
    condition: selection
falsepositives:
    - Unknown
level: critical
