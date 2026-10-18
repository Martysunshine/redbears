<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/identity_protection/azure_identity_protection_unfamilar_sign_in.yml -->
title: Unfamiliar Sign-In Properties
id: 128faeef-79dd-44ca-b43c-a9e236a60f49
status: test
description: Detects sign-in with properties that are unfamiliar to the user. The detection considers past sign-in history to look for anomalous sign-ins.
references:
    - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#unfamiliar-sign-in-properties
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins
author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
date: 2023-09-03
tags:
    - attack.stealth
    - attack.t1078
    - attack.persistence
    - attack.privilege-escalation
    - attack.initial-access
logsource:
    product: azure
    service: riskdetection
detection:
    selection:
        riskEventType: 'unfamiliarFeatures'
    condition: selection
falsepositives:
    - User changing to a new device, location, browser, etc.
level: high
