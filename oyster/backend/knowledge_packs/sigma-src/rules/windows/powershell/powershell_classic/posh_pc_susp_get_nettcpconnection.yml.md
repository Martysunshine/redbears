<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_classic/posh_pc_susp_get_nettcpconnection.yml -->
title: Use Get-NetTCPConnection
id: b366adb4-d63d-422d-8a2c-186463b5ded0
status: test
description: Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md#atomic-test-2---system-network-connections-discovery-with-powershell
author: frack113
date: 2021-12-10
modified: 2023-10-27
tags:
    - attack.discovery
    - attack.t1049
logsource:
    product: windows
    category: ps_classic_start
detection:
    selection:
        Data|contains: 'Get-NetTCPConnection'
    condition: selection
falsepositives:
    - Unknown
level: low
