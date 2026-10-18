<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2023/TA/Peach-Sandstorm/proxy_apt_peach_sandstorm_falsefont_backdoor_c2_coms.yml -->
title: Potential Peach Sandstorm APT C2 Communication Activity
id: b8225208-81d0-4715-a822-12bcdd583e0f
status: test
description: Detects potential C2 communication activity related to Peach Sandstorm APT
references:
    - https://twitter.com/MsftSecIntel/status/1737895710169628824
    - https://www.virustotal.com/gui/file/364275326bbfc4a3b89233dabdaf3230a3d149ab774678342a40644ad9f8d614/details
author: X__Junior (Nextron Systems)
date: 2024-01-15
tags:
    - attack.command-and-control
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        cs-method: 'GET'
        c-uri|endswith:
            - '/api/Core/Command/Init'
            - '/api/Core/Command/Restart'
    condition: selection
falsepositives:
    - Unknown
level: medium
