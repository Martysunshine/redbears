<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_side_load_vivaldi_elf.yml -->
title: Potential Vivaldi_elf.DLL Sideloading
id: 2092cacb-d77b-4f98-ab0d-32b32f99a054
status: test
description: Detects potential DLL sideloading of "vivaldi_elf.dll"
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
        ImageLoaded|endswith: '\vivaldi_elf.dll'
    filter_main_legit_path:
        Image|endswith: '\Vivaldi\Application\vivaldi.exe'
        ImageLoaded|contains: '\Vivaldi\Application\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
