<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml -->
title: Login to Disabled Account
id: 908655e0-25cf-4ae1-b775-1c8ce9cf43d8
status: test
description: Detect failed attempts to sign in to disabled accounts.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts
author: AlertIQ
date: 2021-10-10
modified: 2022-12-25
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.initial-access
    - attack.stealth
    - attack.t1078.004
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        ResultType: 50057
        ResultDescription: 'User account is disabled. The account has been disabled by an administrator.'
    condition: selection
falsepositives:
    - Unknown
level: medium
