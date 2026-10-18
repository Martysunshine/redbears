<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_side_load_solidpdfcreator.yml -->
title: Potential SolidPDFCreator.DLL Sideloading
id: a2edbce1-95c8-4291-8676-0d45146862b3
status: test
description: Detects potential DLL sideloading of "SolidPDFCreator.dll"
references:
    - https://lab52.io/blog/new-mustang-pandas-campaing-against-australia/
author: X__Junior (Nextron Systems)
date: 2023-05-07
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
        ImageLoaded|endswith: '\SolidPDFCreator.dll'
    filter_main_path:
        Image|endswith: '\SolidPDFCreator.exe'
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\SolidDocuments\SolidPDFCreator\'
            - 'C:\Program Files\SolidDocuments\SolidPDFCreator\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
