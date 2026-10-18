<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/m365/threat_management/microsoft365_activity_from_anonymous_ip_addresses.yml -->
title: Activity from Anonymous IP Addresses
id: d8b0a4fe-07a8-41be-bd39-b14afa025d95
status: test
description: Detects when a Microsoft Cloud App Security reported when users were active from an IP address that has been identified as an anonymous proxy IP address.
references:
    - https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
    - https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference
author: Austin Songer @austinsonger
date: 2021-08-23
modified: 2022-10-09
tags:
    - attack.command-and-control
    - attack.t1573
logsource:
    service: threat_management
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Activity from anonymous IP addresses'
        status: success
    condition: selection
falsepositives:
    - User using a VPN or Proxy
level: medium
