<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_user_creation.yml -->
title: Local User Creation
id: 66b6be3d-55d0-4f47-9855-d69df21740ea
status: test
description: |
    Detects local user creation on Windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your Windows server logs and not on your DC logs.
references:
    - https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/
author: Patrick Bareiss
date: 2019-04-18
modified: 2021-01-17
tags:
    - attack.persistence
    - attack.t1136.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
    condition: selection
falsepositives:
    - Domain Controller Logs
    - Local accounts managed by privileged account management tools
level: low
