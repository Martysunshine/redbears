<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_edrsilencer.yml -->
title: HackTool - EDRSilencer Execution
id: eb2d07d4-49cb-4523-801a-da002df36602
status: test
description: |
    Detects the execution of EDRSilencer, a tool that leverages Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server based on PE metadata information.
references:
    - https://github.com/netero1010/EDRSilencer
author: '@gott_cyber'
date: 2024-01-02
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\EDRSilencer.exe'
        - OriginalFileName: 'EDRSilencer.exe'
        - Description|contains: 'EDRSilencer'
    condition: selection
falsepositives:
    - Unlikely
level: high
