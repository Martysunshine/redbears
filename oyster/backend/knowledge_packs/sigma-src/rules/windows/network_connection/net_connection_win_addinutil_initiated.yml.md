<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/network_connection/net_connection_win_addinutil_initiated.yml -->
title: Network Connection Initiated By AddinUtil.EXE
id: 5205613d-2a63-4412-a895-3a2458b587b3
status: test
description: |
    Detects a network connection initiated by the Add-In deployment cache updating utility "AddInutil.exe".
    This could indicate a potential command and control communication as this tool doesn't usually initiate network activity.
references:
    - https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html
author: Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
date: 2023-09-18
modified: 2024-07-16
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        Image|endswith: '\addinutil.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
