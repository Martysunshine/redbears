<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/privileged_identity_management/azure_pim_role_no_mfa_required.yml -->
title: Roles Activation Doesn't Require MFA
id: 94a66f46-5b64-46ce-80b2-75dcbe627cc0
status: test
description: Identifies when a privilege role can be activated without performing mfa.
references:
    - https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#roles-dont-require-multi-factor-authentication-for-activation
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
        riskEventType: 'noMfaOnRoleActivationAlertIncident'
    condition: selection
falsepositives:
    - Investigate if user is performing MFA at sign-in.
level: high
