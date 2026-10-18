<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/account_management/win_security_rdp_localhost_login.yml -->
title: RDP Login from Localhost
id: 51e33403-2a37-4d66-a574-1fda1782cc31
status: test
description: RDP login with localhost source address may be a tunnelled login
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
author: Thomas Patzke
date: 2019-01-28
modified: 2022-10-09
tags:
    - attack.lateral-movement
    - car.2013-07-002
    - attack.t1021.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
        IpAddress:
            - '::1'
            - '127.0.0.1'
    condition: selection
falsepositives:
    - Unknown
level: high
