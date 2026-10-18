<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_ad_bitlocker_key_retrieval.yml -->
title: Bitlocker Key Retrieval
id: a0413867-daf3-43dd-9245-734b3a787942
status: test
description: Monitor and alert for Bitlocker key retrieval.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#bitlocker-key-retrieval
author: Michael Epping, '@mepples21'
date: 2022-06-28
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.initial-access
    - attack.stealth
    - attack.t1078.004
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        Category: KeyManagement
        OperationName: Read BitLocker key
    condition: selection
falsepositives:
    - Unknown
level: medium
