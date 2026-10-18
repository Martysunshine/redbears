<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/identity_protection/azure_identity_protection_anomalous_token.yml -->
title: Anomalous Token
id: 6555754e-5e7f-4a67-ad1c-4041c413a007
status: test
description: Indicates that there are abnormal characteristics in the token such as an unusual token lifetime or a token that is played from an unfamiliar location.
references:
    - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#anomalous-token
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins
author: Mark Morowczynski '@markmorow'
date: 2023-08-07
tags:
    - attack.t1528
    - attack.credential-access
logsource:
    product: azure
    service: riskdetection
detection:
    selection:
        riskEventType: 'anomalousToken'
    condition: selection
falsepositives:
    - We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
level: high
