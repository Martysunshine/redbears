<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_ad_device_registration_policy_changes.yml -->
title: Changes to Device Registration Policy
id: 9494bff8-959f-4440-bbce-fb87a208d517
status: test
description: Monitor and alert for changes to the device registration policy.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#device-registrations-and-joins-outside-policy
author: Michael Epping, '@mepples21'
date: 2022-06-28
tags:
    - attack.privilege-escalation
    - attack.defense-impairment
    - attack.t1484
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        Category: 'Policy'
        ActivityDisplayName: 'Set device registration policies'
    condition: selection
falsepositives:
    - Unknown
level: high
