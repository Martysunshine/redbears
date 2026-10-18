<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/account_management/win_security_diagtrack_eop_default_login_username.yml -->
title: DiagTrackEoP Default Login Username
id: 2111118f-7e46-4fc8-974a-59fd8ec95196
status: test
description: Detects the default "UserName" used by the DiagTrackEoP POC
references:
    - https://github.com/Wh04m1001/DiagTrackEoP/blob/3a2fc99c9700623eb7dc7d4b5f314fd9ce5ef51f/main.cpp#L46
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-03
tags:
    - attack.privilege-escalation
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
        TargetOutboundUserName: 'thisisnotvaliduser'
    condition: selection
falsepositives:
    - Unlikely
level: critical
