<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_hktl_edr_silencer.yml -->
title: HackTool - EDRSilencer Execution - Filter Added
id: 98054878-5eab-434c-85d4-72d4e5a3361b
status: test
description: |
    Detects execution of EDRSilencer, a tool that abuses the Windows Filtering Platform (WFP) to block the outbound traffic of running EDR agents based on specific hardcoded filter names.
references:
    - https://github.com/netero1010/EDRSilencer
author: Thodoris Polyzos (@SmoothDeploy)
date: 2024-01-29
modified: 2024-01-30
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Filtering Platform Policy Change needs to be enabled'
detection:
    selection:
        EventID:
            - 5441
            - 5447
        FilterName|contains: 'Custom Outbound Filter'
    condition: selection
falsepositives:
    - Unknown
level: high
