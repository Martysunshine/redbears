<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_susp_add_domain_trust.yml -->
title: A New Trust Was Created To A Domain
id: 0255a820-e564-4e40-af2b-6ac61160335c
status: stable
description: Addition of domains is seldom and should be verified for legitimacy.
references:
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4706
author: Thomas Patzke
date: 2019-12-03
modified: 2024-01-16
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1098
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4706
    condition: selection
falsepositives:
    - Legitimate extension of domain structure
level: medium
