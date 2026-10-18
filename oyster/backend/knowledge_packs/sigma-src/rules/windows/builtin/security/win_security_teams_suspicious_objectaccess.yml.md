<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_teams_suspicious_objectaccess.yml -->
title: Suspicious Teams Application Related ObjectAcess Event
id: 25cde13e-8e20-4c29-b949-4e795b76f16f
status: test
description: Detects an access to authentication tokens and accounts of Microsoft Teams desktop application.
references:
    - https://www.bleepingcomputer.com/news/security/microsoft-teams-stores-auth-tokens-as-cleartext-in-windows-linux-macs/
    - https://www.vectra.ai/blogpost/undermining-microsoft-teams-security-by-mining-tokens
author: '@SerkinValery'
date: 2022-09-16
tags:
    - attack.credential-access
    - attack.t1528
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4663
        ObjectName|contains:
            - '\Microsoft\Teams\Cookies'
            - '\Microsoft\Teams\Local Storage\leveldb'
    filter:
        ProcessName|contains: '\Microsoft\Teams\current\Teams.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
