<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/account_management/win_security_susp_wmi_login.yml -->
title: Successful Account Login Via WMI
id: 5af54681-df95-4c26-854f-2565e13cfab0
status: stable
description: Detects successful logon attempts performed with WMI
references:
    - Internal Research
author: Thomas Patzke
date: 2019-12-04
modified: 2024-01-17
tags:
    - attack.execution
    - attack.t1047
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        ProcessName|endswith: '\WmiPrvSE.exe'
    condition: selection
falsepositives:
    - Monitoring tools
    - Legitimate system administration
level: low
