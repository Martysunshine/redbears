<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_group_user_addition_ca_modification.yml -->
title: User Added To Group With CA Policy Modification Access
id: 91c95675-1f27-46d0-bead-d1ae96b97cd3
status: test
description: Monitor and alert on group membership additions of groups that have CA policy modification access
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
        properties.message: Add member from group
    condition: selection
falsepositives:
    - User removed from the group is approved
level: medium
