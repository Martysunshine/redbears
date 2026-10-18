<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/privileged_identity_management/azure_pim_invalid_license.yml -->
title: Invalid PIM License
id: 58af08eb-f9e1-43c8-9805-3ad9b0482bd8
status: test
description: Identifies when an organization doesn't have the proper license for PIM and is out of compliance.
references:
    - https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#the-organization-doesnt-have-microsoft-entra-premium-p2-or-microsoft-entra-id-governance
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
        riskEventType: 'invalidLicenseAlertIncident'
    condition: selection
falsepositives:
    - Investigate if licenses have expired.
level: high
