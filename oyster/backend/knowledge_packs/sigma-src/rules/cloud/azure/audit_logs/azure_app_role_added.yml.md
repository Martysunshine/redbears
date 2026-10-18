<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_app_role_added.yml -->
title: App Assigned To Azure RBAC/Microsoft Entra Role
id: b04934b2-0a68-4845-8a19-bdfed3a68a7a
status: test
description: Detects when an app is assigned Azure AD roles, such as global administrator, or Azure RBAC roles, such as subscription owner.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#service-principal-assigned-to-a-role
author: Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
date: 2022-07-19
modified: 2024-11-04
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1098.003
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        targetResources.type: 'Service Principal'
        properties.message:
            - Add member to role
            - Add eligible member to role
            - Add scoped member to role
    condition: selection
falsepositives:
    - When the permission is legitimately needed for the app
level: medium
