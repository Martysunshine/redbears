<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_update_risk_and_mfa_registration_policy.yml -->
title: User Risk and MFA Registration Policy Updated
id: d4c7758e-9417-4f2e-9109-6125d66dabef
status: test
description: |
    Detects changes and updates to the user risk and MFA registration policy.
    Attackers can modified the policies to Bypass MFA, weaken security thresholds, facilitate further attacks, maintain persistence.
references:
    - https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-mfa-policy
    - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
author: Harjot Singh (@cyb3rjy0t)
date: 2024-08-13
tags:
    - attack.persistence
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        LoggedByService: 'AAD Management UX'
        Category: 'Policy'
        OperationName: 'Update User Risk and MFA Registration Policy'
    condition: selection
falsepositives:
    - Known updates by administrators.
level: high
