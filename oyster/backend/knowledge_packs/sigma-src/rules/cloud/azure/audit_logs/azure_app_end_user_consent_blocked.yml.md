<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_app_end_user_consent_blocked.yml -->
title: End User Consent Blocked
id: 7091372f-623c-4293-bc37-20c32b3492be
status: test
description: Detects when end user consent is blocked due to risk-based consent.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#end-user-stopped-due-to-risk-based-consent
author: Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
date: 2022-07-10
tags:
    - attack.credential-access
    - attack.t1528
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        failure_status_reason: 'Microsoft.online.Security.userConsentBlockedForRiskyAppsExceptions'
    condition: selection
falsepositives:
    - Unknown
level: medium
