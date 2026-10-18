<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/signin_logs/azure_ad_azurehound_discovery.yml -->
title: Discovery Using AzureHound
id: 35b781cc-1a08-4a5a-80af-42fd7c315c6b
status: test
description: Detects AzureHound (A BloodHound data collector for Microsoft Azure) activity via the default User-Agent that is used during its operation after successful authentication.
references:
    - https://github.com/BloodHoundAD/AzureHound
author: Janantha Marasinghe
date: 2022-11-27
tags:
    - attack.discovery
    - attack.t1087.004
    - attack.t1526
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        userAgent|contains: 'azurehound'
        ResultType: 0
    condition: selection
falsepositives:
    - Unknown
level: high
