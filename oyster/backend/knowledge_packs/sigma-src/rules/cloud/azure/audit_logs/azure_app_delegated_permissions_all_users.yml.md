<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_app_delegated_permissions_all_users.yml -->
title: Delegated Permissions Granted For All Users
id: a6355fbe-f36f-45d8-8efc-ab42465cbc52
status: test
description: Detects when highly privileged delegated permissions are granted on behalf of all users
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#application-granted-highly-privileged-permissions
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
        properties.message: Add delegated permission grant
    condition: selection
falsepositives:
    - When the permission is legitimately needed for the app
level: high
