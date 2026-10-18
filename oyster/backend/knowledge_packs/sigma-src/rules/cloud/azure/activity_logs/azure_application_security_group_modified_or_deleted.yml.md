<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/activity_logs/azure_application_security_group_modified_or_deleted.yml -->
title: Azure Application Security Group Modified or Deleted
id: 835747f1-9329-40b5-9cc3-97d465754ce6
status: test
description: Identifies when a application security group is modified or deleted.
references:
    - https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
author: Austin Songer
date: 2021-08-16
modified: 2022-08-23
tags:
    - attack.impact
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName:
            - MICROSOFT.NETWORK/APPLICATIONSECURITYGROUPS/WRITE
            - MICROSOFT.NETWORK/APPLICATIONSECURITYGROUPS/DELETE
    condition: selection
falsepositives:
    - Application security group being modified or deleted may be performed by a system administrator.
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Application security group modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium
