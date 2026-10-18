<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_susp_net_recon_activity.yml -->
title: Reconnaissance Activity
id: 968eef52-9cff-4454-8992-1e74b9cbad6c
status: test
description: Detects activity as "net user administrator /domain" and "net group domain admins /domain"
references:
    - https://findingbad.blogspot.de/2017/01/hunting-what-does-it-look-like.html
author: Florian Roth (Nextron Systems), Jack Croock (method), Jonhnathan Ribeiro (improvements), oscd.community
date: 2017-03-07
modified: 2022-08-22
tags:
    - attack.discovery
    - attack.t1087.002
    - attack.t1069.002
    - attack.s0039
logsource:
    product: windows
    service: security
    definition: The volume of Event ID 4661 is high on Domain Controllers and therefore "Audit SAM" and "Audit Kernel Object" advanced audit policy settings are not configured in the recommendations for server systems
detection:
    selection:
        EventID: 4661
        AccessMask: '0x2d'
        ObjectType:
            - 'SAM_USER'
            - 'SAM_GROUP'
        ObjectName|startswith: 'S-1-5-21-'
        ObjectName|endswith:
            - '-500'
            - '-512'
    condition: selection
falsepositives:
    - Administrator activity
level: high
