<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/signin_logs/azure_ad_risky_sign_ins_with_singlefactorauth_from_unknown_devices.yml -->
title: Suspicious SignIns From A Non Registered Device
id: 572b12d4-9062-11ed-a1eb-0242ac120002
status: test
description: Detects risky authentication from a non AD registered device without MFA being required.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#non-compliant-device-sign-in
author: Harjot Singh, '@cyb3rjy0t'
date: 2023-01-10
modified: 2025-07-02
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.initial-access
    - attack.stealth
    - attack.t1078
logsource:
    product: azure
    service: signinlogs
detection:
    selection_main:
        Status: 'Success'
        AuthenticationRequirement: 'singleFactorAuthentication'
        RiskState: 'atRisk'
    selection_empty1:
        DeviceDetail.trusttype: ''
    selection_empty2:
        DeviceDetail.trusttype: null
    condition: selection_main and 1 of selection_empty*
falsepositives:
    - Unknown
level: high
