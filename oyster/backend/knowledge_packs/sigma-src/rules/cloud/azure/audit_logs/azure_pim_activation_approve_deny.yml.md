<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_pim_activation_approve_deny.yml -->
title: PIM Approvals And Deny Elevation
id: 039a7469-0296-4450-84c0-f6966b16dc6d
status: test
description: Detects when a PIM elevation is approved or denied. Outside of normal operations should be investigated.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-identity-management#azure-ad-roles-assignment
author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
date: 2022-08-09
tags:
    - attack.persistence
    - attack.initial-access
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1078.004
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Request Approved/Denied
    condition: selection
falsepositives:
    - Actual admin using PIM.
level: high
