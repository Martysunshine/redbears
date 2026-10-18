<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/process_creation/proc_creation_win_susp_exfil_and_tunneling_tool_execution.yml -->
title: Tunneling Tool Execution
id: c75309a3-59f8-4a8d-9c2c-4c927ad50555
status: test
description: Detects the execution of well known tools that can be abused for data exfiltration and tunneling.
author: Daniil Yugoslavskiy, oscd.community
references:
    - https://www.microsoft.com/en-us/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
date: 2019-10-24
modified: 2024-01-18
tags:
    - attack.exfiltration
    - attack.command-and-control
    - attack.t1041
    - attack.t1572
    - attack.t1071.001
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\httptunnel.exe'
            - '\plink.exe'
            - '\socat.exe'
            - '\stunnel.exe'
    condition: selection
falsepositives:
    - Legitimate administrators using one of these tools
level: medium
