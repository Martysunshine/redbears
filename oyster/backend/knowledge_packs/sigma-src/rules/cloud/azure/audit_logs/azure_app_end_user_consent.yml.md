<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_app_end_user_consent.yml -->
title: End User Consent
id: 9b2cc4c4-2ad4-416d-8e8e-ee6aa6f5035a
status: test
description: Detects when an end user consents to an application
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#end-user-consent
author: Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
date: 2022-07-28
tags:
    - attack.credential-access
    - attack.t1528
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        ConsentContext.IsAdminConsent: 'false'
    condition: selection
falsepositives:
    - Unknown
level: low
