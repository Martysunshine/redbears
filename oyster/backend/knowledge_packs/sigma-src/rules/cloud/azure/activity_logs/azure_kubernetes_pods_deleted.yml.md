<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/activity_logs/azure_kubernetes_pods_deleted.yml -->
title: Azure Kubernetes Pods Deleted
id: b02f9591-12c3-4965-986a-88028629b2e1
status: test
description: Identifies the deletion of Azure Kubernetes Pods.
references:
    - https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
    - https://github.com/elastic/detection-rules/blob/065bf48a9987cd8bd826c098a30ce36e6868ee46/rules/integrations/azure/impact_kubernetes_pod_deleted.toml
author: Austin Songer @austinsonger
date: 2021-07-24
modified: 2022-08-23
tags:
    - attack.impact
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName: MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE
    condition: selection
falsepositives:
    - Pods may be deleted by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Pods deletions from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium
