<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/file/file_event/file_event_win_vscode_tunnel_indicators.yml -->
title: VsCode Code Tunnel Execution File Indicator
id: 9661ec9d-4439-4a7a-abed-d9be4ca43b6d
status: test
description: |
    Detects the creation of a file with the name "code_tunnel.json" which indicate execution and usage of VsCode tunneling utility. Attackers can abuse this functionality to establish a C2 channel
references:
    - https://ipfyx.fr/post/visual-studio-code-tunnel/
    - https://badoption.eu/blog/2023/01/31/code_c2.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-10-25
tags:
    - attack.command-and-control
    - detection.threat-hunting
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\code_tunnel.json'
    condition: selection
falsepositives:
    - Legitimate usage of VsCode tunneling functionality will also trigger this
level: medium
