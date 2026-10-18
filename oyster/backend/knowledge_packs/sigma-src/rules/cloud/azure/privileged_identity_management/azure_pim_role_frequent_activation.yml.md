<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/privileged_identity_management/azure_pim_role_frequent_activation.yml -->
title: Roles Activated Too Frequently
id: 645fd80d-6c07-435b-9e06-7bc1b5656cba
status: test
description: Identifies when the same privilege role has multiple activations by the same user.
references:
    - https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#roles-are-being-activated-too-frequently
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
        riskEventType: 'sequentialActivationRenewalsAlertIncident'
    condition: selection
falsepositives:
    - Investigate where if active time period for a role is set too short.
level: high
