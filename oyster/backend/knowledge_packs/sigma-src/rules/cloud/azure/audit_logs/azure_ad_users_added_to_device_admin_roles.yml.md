<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_ad_users_added_to_device_admin_roles.yml -->
title: Users Added to Global or Device Admin Roles
id: 11c767ae-500b-423b-bae3-b234450736ed
status: test
description: Monitor and alert for users added to device admin roles.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#device-administrator-roles
author: Michael Epping, '@mepples21'
date: 2022-06-28
tags:
    - attack.persistence
    - attack.initial-access
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1078.004
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        Category: RoleManagement
        OperationName|contains|all:
            - 'Add'
            - 'member to role'
        TargetResources|contains:
            - '7698a772-787b-4ac8-901f-60d6b08affd2'
            - '62e90394-69f5-4237-9190-012177145e10'
    condition: selection
falsepositives:
    - Unknown
level: high
