<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_dll_pcre_dotnet_dll_load.yml -->
title: PCRE.NET Package Image Load
id: 84b0a8f3-680b-4096-a45b-e9a89221727c
status: test
description: Detects processes loading modules related to PCRE.NET package
references:
    - https://twitter.com/rbmaslen/status/1321859647091970051
    - https://twitter.com/tifkin_/status/1321916444557365248
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-10-29
modified: 2022-10-09
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|contains: \AppData\Local\Temp\ba9ea7344a4a5f591d6e5dc32a13494b\
    condition: selection
falsepositives:
    - Unknown
level: high
