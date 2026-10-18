<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/account_management/win_security_susp_logon_newcredentials.yml -->
title: Outgoing Logon with New Credentials
id: def8b624-e08f-4ae1-8612-1ba21190da6b
status: test
description: Detects logon events that specify new credentials
references:
    - https://go.recordedfuture.com/hubfs/reports/mtp-2021-0914.pdf
author: Max Altgelt (Nextron Systems)
date: 2022-04-06
tags:
    - attack.lateral-movement
    - attack.t1550
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
    condition: selection
falsepositives:
    - Legitimate remote administration activity
level: low
