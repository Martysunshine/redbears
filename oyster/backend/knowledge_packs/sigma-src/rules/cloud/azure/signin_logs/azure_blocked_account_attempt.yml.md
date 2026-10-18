<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/signin_logs/azure_blocked_account_attempt.yml -->
title: Account Disabled or Blocked for Sign in Attempts
id: 4afac85c-224a-4dd7-b1af-8da40e1c60bd
status: test
description: Detects when an account is disabled or blocked for sign in but tried to log in
references:
    - https://learn.microsoft.com/en-gb/entra/architecture/security-operations-privileged-accounts
author: Yochana Henderson, '@Yochana-H'
date: 2022-06-17
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
        ResultDescription: Failure
    condition: selection
falsepositives:
    - Account disabled or blocked in error
    - Automation account has been blocked or disabled
level: medium
