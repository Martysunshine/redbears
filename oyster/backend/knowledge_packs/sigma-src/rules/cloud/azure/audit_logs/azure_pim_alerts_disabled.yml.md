<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_pim_alerts_disabled.yml -->
title: PIM Alert Setting Changes To Disabled
id: aeaef14c-e5bf-4690-a9c8-835caad458bd
status: test
description: Detects when PIM alerts are set to disabled.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-identity-management#azure-ad-roles-assignment
author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
date: 2022-08-09
tags:
    - attack.initial-access
    - attack.persistence
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1078
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Disable PIM Alert
    condition: selection
falsepositives:
    - Administrator disabling PIM alerts as an active choice.
level: high
