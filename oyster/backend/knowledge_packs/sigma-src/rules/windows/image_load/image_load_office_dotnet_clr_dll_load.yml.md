<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_office_dotnet_clr_dll_load.yml -->
title: CLR DLL Loaded Via Office Applications
id: d13c43f0-f66b-4279-8b2c-5912077c1780
status: test
description: Detects CLR DLL being loaded by an Office Product
references:
    - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
author: Antonlovesdnb
date: 2020-02-19
modified: 2023-03-29
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith:
            - '\excel.exe'
            - '\mspub.exe'
            - '\outlook.exe'
            - '\onenote.exe'
            - '\onenoteim.exe' # Just in case
            - '\powerpnt.exe'
            - '\winword.exe'
        ImageLoaded|contains: '\clr.dll'
    condition: selection
falsepositives:
    - Unknown
level: medium
