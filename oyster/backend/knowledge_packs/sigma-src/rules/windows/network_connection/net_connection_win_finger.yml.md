<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/network_connection/net_connection_win_finger.yml -->
title: Network Connection Initiated via Finger.EXE
id: 2fdaf50b-9fd5-449f-ba69-f17248119af6
related:
    - id: c082c2b0-525b-4dbc-9a26-a57dc4692074
      type: similar
    - id: af491bca-e752-4b44-9c86-df5680533dbc
      type: similar
status: experimental
description: |
    Detects network connections via finger.exe, which can be abused by threat actors to retrieve remote commands for execution on Windows devices.
    In one ClickFix malware campaign, adversaries leveraged the finger protocol to fetch commands from a remote server.
    Since the finger utility is not commonly used in modern Windows environments, its presence already raises suspicion.
    Investigating such network connections can also help identify potential malicious infrastructure used by threat actors
references:
    - https://www.bleepingcomputer.com/news/security/decades-old-finger-protocol-abused-in-clickfix-malware-attacks/
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-11-19
tags:
    - attack.command-and-control
    - attack.t1071.004
    - attack.execution
    - attack.t1059.003
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        Image|endswith: '\finger.exe'
    condition: selection
falsepositives:
    - Unlikely
level: high
