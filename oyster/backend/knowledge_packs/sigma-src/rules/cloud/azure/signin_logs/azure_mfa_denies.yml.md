<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/signin_logs/azure_mfa_denies.yml -->
title: Multifactor Authentication Denied
id: e40f4962-b02b-4192-9bfe-245f7ece1f99
status: test
description: User has indicated they haven't instigated the MFA prompt and could indicate an attacker has the password for the account.
references:
    - https://www.microsoft.com/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/
author: AlertIQ
date: 2022-03-24
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.initial-access
    - attack.credential-access
    - attack.stealth
    - attack.t1078.004
    - attack.t1110
    - attack.t1621
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        AuthenticationRequirement: 'multiFactorAuthentication'
        Status|contains: 'MFA Denied'
    condition: selection
falsepositives:
    - Users actually login but miss-click into the Deny button when MFA prompt.
level: medium
