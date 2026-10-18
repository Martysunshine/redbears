<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_register_new_logon_process_by_rubeus.yml -->
title: Register new Logon Process by Rubeus
id: 12e6d621-194f-4f59-90cc-1959e21e69f7
status: test
description: Detects potential use of Rubeus via registered new trusted logon process
references:
    - https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
author: Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community
date: 2019-10-24
modified: 2022-10-09
tags:
    - attack.lateral-movement
    - attack.privilege-escalation
    - attack.credential-access
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4611
        LogonProcessName: 'User32LogonProcesss'
    condition: selection
falsepositives:
    - Unknown
level: high
