<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/activity_logs/azure_aadhybridhealth_adfs_service_delete.yml -->
title: Azure Active Directory Hybrid Health AD FS Service Delete
id: 48739819-8230-4ee3-a8ea-e0289d1fb0ff
status: test
description: |
    This detection uses azureactivity logs (Administrative category) to identify the deletion of an Azure AD Hybrid health AD FS service instance in a tenant.
    A threat actor can create a new AD Health ADFS service and create a fake server to spoof AD FS signing logs.
    The health AD FS service can then be deleted after it is not longer needed via HTTP requests to Azure.
references:
    - https://o365blog.com/post/hybridhealthagent/
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: 2021-08-26
modified: 2023-10-11
tags:
    - attack.defense-impairment
    - attack.t1578.003
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        CategoryValue: 'Administrative'
        ResourceProviderValue: 'Microsoft.ADHybridHealthService'
        ResourceId|contains: 'AdFederationService'
        OperationNameValue: 'Microsoft.ADHybridHealthService/services/delete'
    condition: selection
falsepositives:
    - Legitimate AAD Health AD FS service instances being deleted in a tenant
level: medium
