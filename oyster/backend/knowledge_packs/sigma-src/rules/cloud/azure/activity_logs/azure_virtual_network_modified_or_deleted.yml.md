<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/activity_logs/azure_virtual_network_modified_or_deleted.yml -->
title: Azure Virtual Network Modified or Deleted
id: bcfcc962-0e4a-4fd9-84bb-a833e672df3f
status: test
description: Identifies when a Virtual Network is modified or deleted in Azure.
references:
    - https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
author: Austin Songer @austinsonger
date: 2021-08-08
modified: 2022-08-23
tags:
    - attack.impact
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName|startswith:
            - MICROSOFT.NETWORK/VIRTUALNETWORKGATEWAYS/
            - MICROSOFT.NETWORK/VIRTUALNETWORKS/
        operationName|endswith:
            - /WRITE
            - /DELETE
    condition: selection
falsepositives:
    - Virtual Network being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Virtual Network modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium
