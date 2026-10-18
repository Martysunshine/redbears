<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/signin_logs/azure_ad_only_single_factor_auth_required.yml -->
title: Azure AD Only Single Factor Authentication Required
id: 28eea407-28d7-4e42-b0be-575d5ba60b2c
status: test
description: Detect when users are authenticating without MFA being required.
references:
    - https://learn.microsoft.com/en-gb/entra/architecture/security-operations-user-accounts
author: MikeDuddington, '@dudders1'
date: 2022-07-27
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.initial-access
    - attack.credential-access
    - attack.stealth
    - attack.defense-impairment
    - attack.t1078.004
    - attack.t1556.006
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        Status: 'Success'
        AuthenticationRequirement: 'singleFactorAuthentication'
    condition: selection
falsepositives:
    - If this was approved by System Administrator.
level: low
