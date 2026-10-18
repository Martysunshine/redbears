<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_side_load_eacore.yml -->
title: Potential EACore.DLL Sideloading
id: edd3ddc3-386f-4ba5-9ada-4376b2cfa7b5
status: test
description: Detects potential DLL sideloading of "EACore.dll"
references:
    - https://research.checkpoint.com/2023/beyond-the-horizon-traveling-the-world-on-camaro-dragons-usb-flash-drives/
author: X__Junior (Nextron Systems)
date: 2023-08-03
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
        ImageLoaded|endswith: '\EACore.dll'
    filter_main_legit_path:
        Image|contains|all:
            - 'C:\Program Files\Electronic Arts\EA Desktop\'
            - '\EACoreServer.exe'
        ImageLoaded|startswith: 'C:\Program Files\Electronic Arts\EA Desktop\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
