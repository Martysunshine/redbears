<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_wmiprvse_wbemcomn_dll_hijack.yml -->
title: Wmiprvse Wbemcomn DLL Hijack
id: 7707a579-e0d8-4886-a853-ce47e4575aaa
status: test
description: Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network and loading it for a WMI DLL Hijack scenario.
references:
    - https://threathunterplaybook.com/hunts/windows/201009-RemoteWMIWbemcomnDLLHijack/notebook.html
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-10-12
modified: 2022-10-09
tags:
    - attack.execution
    - attack.t1047
    - attack.lateral-movement
    - attack.t1021.002
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Image|endswith: '\wmiprvse.exe'
        ImageLoaded|endswith: '\wbem\wbemcomn.dll'
    condition: selection
falsepositives:
    - Unknown
level: high
