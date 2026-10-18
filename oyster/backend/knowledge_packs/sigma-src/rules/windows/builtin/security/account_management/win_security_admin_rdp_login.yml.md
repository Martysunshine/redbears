<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/account_management/win_security_admin_rdp_login.yml -->
title: Admin User Remote Logon
id: 0f63e1ef-1eb9-4226-9d54-8927ca08520a
status: test
description: Detect remote login by Administrator user (depending on internal pattern).
references:
    - https://car.mitre.org/wiki/CAR-2016-04-005
author: juju4
date: 2017-10-29
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.lateral-movement
    - attack.initial-access
    - attack.stealth
    - attack.t1078.001
    - attack.t1078.002
    - attack.t1078.003
    - car.2016-04-005
logsource:
    product: windows
    service: security
    definition: 'Requirements: Identifiable administrators usernames (pattern or special unique character. ex: "Admin-*"), internal policy mandating use only as secondary account'
detection:
    selection:
        EventID: 4624
        LogonType: 10
        AuthenticationPackageName: Negotiate
        TargetUserName|startswith: 'Admin'
    condition: selection
falsepositives:
    - Legitimate administrative activity.
level: low
