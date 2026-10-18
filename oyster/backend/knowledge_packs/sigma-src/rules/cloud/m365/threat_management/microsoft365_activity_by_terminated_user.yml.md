<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/m365/threat_management/microsoft365_activity_by_terminated_user.yml -->
title: Activity Performed by Terminated User
id: 2e669ed8-742e-4fe5-b3c4-5a59b486c2ee
status: test
description: |
  Detects when a Microsoft Cloud App Security reported for users whose account were terminated in Azure AD, but still perform activities in other platforms such as AWS or Salesforce.
  This is especially relevant for users who use another account to manage resources, since these accounts are often not terminated when a user leaves the company.
references:
    - https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
    - https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference
author: Austin Songer @austinsonger
date: 2021-08-23
modified: 2022-10-09
tags:
    - attack.impact
logsource:
    service: threat_management
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Activity performed by terminated user'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium
