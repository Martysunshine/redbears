<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/identity_protection/azure_identity_protection_leaked_credentials.yml -->
title: Azure AD Account Credential Leaked
id: 19128e5e-4743-48dc-bd97-52e5775af817
status: test
description: Indicates that the user's valid credentials have been leaked.
references:
    - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#leaked-credentials
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins
author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
date: 2023-09-03
tags:
    - attack.t1589
    - attack.reconnaissance
logsource:
    product: azure
    service: riskdetection
detection:
    selection:
        riskEventType: 'leakedCredentials'
    condition: selection
falsepositives:
    - A rare hash collision.
level: high
