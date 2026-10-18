<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/signin_logs/azure_ad_sign_ins_from_noncompliant_devices.yml -->
title: Sign-ins from Non-Compliant Devices
id: 4f77e1d7-3982-4ee0-8489-abf2d6b75284
status: test
description: Monitor and alert for sign-ins where the device was non-compliant.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#non-compliant-device-sign-in
author: Michael Epping, '@mepples21'
date: 2022-06-28
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
        DeviceDetail.isCompliant: 'false'
    condition: selection
falsepositives:
    - Unknown
level: high
