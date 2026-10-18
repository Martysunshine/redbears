<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/m365/threat_management/microsoft365_unusual_volume_of_file_deletion.yml -->
title: Microsoft 365 - Unusual Volume of File Deletion
id: 78a34b67-3c39-4886-8fb4-61c46dc18ecd
status: test
description: Detects when a Microsoft Cloud App Security reported a user has deleted a unusual a large volume of files.
references:
    - https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
    - https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference
author: austinsonger
date: 2021-08-19
modified: 2022-10-09
tags:
    - attack.impact
    - attack.t1485
logsource:
    service: threat_management
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Unusual volume of file deletion'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium
