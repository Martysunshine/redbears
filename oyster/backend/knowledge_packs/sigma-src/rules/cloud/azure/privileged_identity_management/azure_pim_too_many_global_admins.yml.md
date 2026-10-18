<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/privileged_identity_management/azure_pim_too_many_global_admins.yml -->
title: Too Many Global Admins
id: 7bbc309f-e2b1-4eb1-8369-131a367d67d3
status: test
description: Identifies an event where there are there are too many accounts assigned the Global Administrator role.
references:
    - https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#there-are-too-many-global-administrators
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
        riskEventType: 'tooManyGlobalAdminsAssignedToTenantAlertIncident'
    condition: selection
falsepositives:
    - Investigate if threshold setting in PIM is too low.
level: high
