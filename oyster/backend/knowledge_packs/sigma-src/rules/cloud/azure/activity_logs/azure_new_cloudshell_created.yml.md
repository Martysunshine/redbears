<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/activity_logs/azure_new_cloudshell_created.yml -->
title: Azure New CloudShell Created
id: 72af37e2-ec32-47dc-992b-bc288a2708cb
status: test
description: Identifies when a new cloudshell is created inside of Azure portal.
references:
    - https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
author: Austin Songer
date: 2021-09-21
modified: 2022-08-23
tags:
    - attack.execution
    - attack.t1059
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName: MICROSOFT.PORTAL/CONSOLES/WRITE
    condition: selection
falsepositives:
    - A new cloudshell may be created by a system administrator.
level: medium
