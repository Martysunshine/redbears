<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_group_user_removal_ca_modification.yml -->
title: User Removed From Group With CA Policy Modification Access
id: 665e2d43-70dc-4ccc-9d27-026c9dd7ed9c
status: test
description: Monitor and alert on group membership removal of groups that have CA policy modification access
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-infrastructure#conditional-access
author: Mark Morowczynski '@markmorow', Thomas Detzner '@tdetzner'
date: 2022-08-04
tags:
    - attack.privilege-escalation
    - attack.credential-access
    - attack.persistence
    - attack.defense-impairment
    - attack.t1548
    - attack.t1556
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Remove member from group
    condition: selection
falsepositives:
    - User removed from the group is approved
level: medium
