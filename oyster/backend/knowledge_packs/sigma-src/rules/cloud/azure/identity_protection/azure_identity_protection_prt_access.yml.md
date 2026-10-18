<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/identity_protection/azure_identity_protection_prt_access.yml -->
title: Primary Refresh Token Access Attempt
id: a84fc3b1-c9ce-4125-8e74-bdcdb24021f1
status: test
description: Indicates access attempt to the PRT resource which can be used to move laterally into an organization or perform credential theft
references:
    - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#possible-attempt-to-access-primary-refresh-token-prt
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins
author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
date: 2023-09-07
tags:
    - attack.t1528
    - attack.credential-access
logsource:
    product: azure
    service: riskdetection
detection:
    selection:
        riskEventType: 'attemptedPrtAccess'
    condition: selection
falsepositives:
    - This detection is low-volume and is seen infrequently in most organizations. When this detection appears it's high risk, and users should be remediated.
level: high
