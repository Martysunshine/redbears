<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/network_connection/net_connection_win_msiexec_http.yml -->
title: Msiexec.EXE Initiated Network Connection Over HTTP
id: 8e5e38e4-5350-4c0b-895a-e872ce0dd54f
status: test
description: |
    Detects a network connection initiated by an "Msiexec.exe" process over port 80 or 443.
    Adversaries might abuse "msiexec.exe" to install and execute remotely hosted packages.
    Use this rule to hunt for potentially anomalous or suspicious communications.
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md
author: frack113
date: 2022-01-16
modified: 2024-07-16
tags:
    - attack.stealth
    - attack.t1218.007
    - detection.threat-hunting
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        Image|endswith: '\msiexec.exe'
        DestinationPort:
            - 80
            - 443
    condition: selection
falsepositives:
    - Likely
level: low
