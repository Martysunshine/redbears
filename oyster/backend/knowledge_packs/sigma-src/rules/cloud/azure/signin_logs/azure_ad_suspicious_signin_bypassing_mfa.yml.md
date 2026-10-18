<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/signin_logs/azure_ad_suspicious_signin_bypassing_mfa.yml -->
title: Potential MFA Bypass Using Legacy Client Authentication
id: 53bb4f7f-48a8-4475-ac30-5a82ddfdf6fc
status: test
description: Detects successful authentication from potential clients using legacy authentication via user agent strings. This could be a sign of MFA bypass using a password spray attack.
references:
    - https://web.archive.org/web/20230217071802/https://blooteem.com/march-2022
    - https://www.microsoft.com/en-us/security/blog/2021/10/26/protect-your-business-from-password-sprays-with-microsoft-dart-recommendations/
author: Harjot Singh, '@cyb3rjy0t'
date: 2023-03-20
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.initial-access
    - attack.credential-access
    - attack.stealth
    - attack.t1078.004
    - attack.t1110
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        Status: 'Success'
        userAgent|contains:
            - 'BAV2ROPC'
            - 'CBAinPROD'
            - 'CBAinTAR'
    condition: selection
falsepositives:
    - Known Legacy Accounts
level: high
