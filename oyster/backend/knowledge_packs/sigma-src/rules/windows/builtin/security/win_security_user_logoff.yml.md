<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_user_logoff.yml -->
title: User Logoff Event
id: 0badd08f-c6a3-4630-90d3-6875cca440be
status: test
description: Detects a user log-off activity. Could be used for example to correlate information during forensic investigations
references:
    - https://github.com/Yamato-Security/EnableWindowsLogSettings/blob/7f6d755d45ac7cc9fc35b0cbf498e6aa4ef19def/ConfiguringSecurityLogAuditPolicies.md
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647
author: frack113
date: 2022-10-14
tags:
    - attack.impact
    - attack.t1531
logsource:
    service: security
    product: windows
detection:
    selection:
        EventID:
            - 4634
            - 4647
    condition: selection
falsepositives:
    - Unknown
level: informational
