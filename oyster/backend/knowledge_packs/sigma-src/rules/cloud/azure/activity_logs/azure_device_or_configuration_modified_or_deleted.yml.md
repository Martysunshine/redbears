<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/activity_logs/azure_device_or_configuration_modified_or_deleted.yml -->
title: Azure Device or Configuration Modified or Deleted
id: 46530378-f9db-4af9-a9e5-889c177d3881
status: test
description: Identifies when a device or device configuration in azure is modified or deleted.
references:
    - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities#core-directory
author: Austin Songer @austinsonger
date: 2021-09-03
modified: 2022-10-09
tags:
    - attack.impact
    - attack.t1485
    - attack.t1565.001
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        properties.message:
            - Delete device
            - Delete device configuration
            - Update device
            - Update device configuration
    condition: selection
falsepositives:
    - Device or device configuration being modified or deleted may be performed by a system administrator.
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Device or device configuration modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium
