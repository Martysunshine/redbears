<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_hybridconnectionmgr_svc_installation.yml -->
title: HybridConnectionManager Service Installation
id: 0ee4d8a5-4e67-4faf-acfa-62a78457d1f2
status: test
description: Rule to detect the Hybrid Connection Manager service installation.
references:
    - https://twitter.com/Cyb3rWard0g/status/1381642789369286662
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2021-04-12
modified: 2022-10-09
tags:
    - attack.persistence
    - attack.t1554
logsource:
    product: windows
    service: security
    definition: The 'System Security Extension' audit subcategory need to be enabled to log the EID 4697
detection:
    selection:
        EventID: 4697
        ServiceName: HybridConnectionManager
        ServiceFileName|contains: HybridConnectionManager
    condition: selection
falsepositives:
    - Legitimate use of Hybrid Connection Manager via Azure function apps.
level: high
