<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/privileged_identity_management/azure_pim_role_assigned_outside_of_pim.yml -->
title: Roles Assigned Outside PIM
id: b1bc08d1-8224-4758-a0e6-fbcfc98c73bb
status: test
description: Identifies when a privilege role assignment has taken place outside of PIM and may indicate an attack.
references:
    - https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#roles-are-being-assigned-outside-of-privileged-identity-management
author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
date: 2023-09-14
tags:
    - attack.initial-access
    - attack.stealth
    - attack.t1078
    - attack.persistence
    - attack.privilege-escalation
logsource:
    product: azure
    service: pim
detection:
    selection:
        riskEventType: 'rolesAssignedOutsidePrivilegedIdentityManagementAlertConfiguration'
    condition: selection
falsepositives:
    - Investigate where users are being assigned privileged roles outside of Privileged Identity Management and prohibit future assignments from there.
level: high
