<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_aad_secops_new_ca_policy_addedby_bad_actor.yml -->
title: New CA Policy by Non-approved Actor
id: 0922467f-db53-4348-b7bf-dee8d0d348c6
status: test
description: Monitor and alert on conditional access changes.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-infrastructure
author: Corissa Koopmans, '@corissalea'
date: 2022-07-18
tags:
    - attack.privilege-escalation
    - attack.t1548
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Add conditional access policy
    condition: selection
falsepositives:
    - Misconfigured role permissions
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
level: medium
