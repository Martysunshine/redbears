<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_side_load_avkkid.yml -->
title: Potential AVKkid.DLL Sideloading
id: 952ed57c-8f99-453d-aee0-53a49c22f95d
status: test
description: Detects potential DLL sideloading of "AVKkid.dll"
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
        ImageLoaded|endswith: '\AVKkid.dll'
    filter_main_legit_path:
        Image|contains:
            - 'C:\Program Files (x86)\G DATA\'
            - 'C:\Program Files\G DATA\'
        Image|endswith: '\AVKKid.exe'
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\G DATA\'
            - 'C:\Program Files\G DATA\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
