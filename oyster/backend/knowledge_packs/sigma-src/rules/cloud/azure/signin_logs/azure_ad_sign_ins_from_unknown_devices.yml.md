<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/signin_logs/azure_ad_sign_ins_from_unknown_devices.yml -->
title: Sign-ins by Unknown Devices
id: 4d136857-6a1a-432a-82fc-5dd497ee5e7c
status: test
description: Monitor and alert for Sign-ins by unknown devices from non-Trusted locations.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#non-compliant-device-sign-in
author: Michael Epping, '@mepples21'
date: 2022-06-28
modified: 2022-10-05
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
        AuthenticationRequirement: singleFactorAuthentication
        ResultType: 0
        NetworkLocationDetails: '[]'
        DeviceDetail.deviceId: ''
    condition: selection
falsepositives:
    - Unknown
level: low
