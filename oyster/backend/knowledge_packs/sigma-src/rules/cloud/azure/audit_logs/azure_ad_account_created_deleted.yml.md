<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_ad_account_created_deleted.yml -->
title: Account Created And Deleted Within A Close Time Frame
id: 6f583da0-3a90-4566-a4ed-83c09fe18bbf
status: test
description: Detects when an account was created and deleted in a short period of time.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#short-lived-accounts
author: Mark Morowczynski '@markmorow', MikeDuddington, '@dudders1', Tim Shelton
date: 2022-08-11
modified: 2022-08-18
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.initial-access
    - attack.stealth
    - attack.t1078
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message:
            - Add user
            - Delete user
        Status: Success
    condition: selection
falsepositives:
    - Legit administrative action
level: high
