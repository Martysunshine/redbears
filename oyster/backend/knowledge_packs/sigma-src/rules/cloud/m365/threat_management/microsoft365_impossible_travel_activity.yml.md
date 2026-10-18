<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/m365/threat_management/microsoft365_impossible_travel_activity.yml -->
title: Microsoft 365 - Impossible Travel Activity
id: d7eab125-5f94-43df-8710-795b80fa1189
status: test
description: Detects when a Microsoft Cloud App Security reported a risky sign-in attempt due to a login associated with an impossible travel.
references:
    - https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
    - https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference
author: Austin Songer @austinsonger
date: 2020-07-06
modified: 2021-11-27
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.initial-access
    - attack.stealth
    - attack.t1078
logsource:
    service: threat_management
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Impossible travel activity'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium
