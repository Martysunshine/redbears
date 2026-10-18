<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/privileged_identity_management/azure_pim_role_not_used.yml -->
title: Roles Are Not Being Used
id: 8c6ec464-4ae4-43ac-936a-291da66ed13d
status: test
description: Identifies when a user has been assigned a privilege role and are not using that role.
references:
    - https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#administrators-arent-using-their-privileged-roles
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
        riskEventType: 'redundantAssignmentAlertIncident'
    condition: selection
falsepositives:
    - Investigate if potential generic account that cannot be removed.
level: high
