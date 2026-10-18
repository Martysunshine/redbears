<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/gcp/audit/gcp_dns_zone_modified_or_deleted.yml -->
title: Google Cloud DNS Zone Modified or Deleted
id: 28268a8f-191f-4c17-85b2-f5aa4fa829c3
status: test
description: Identifies when a DNS Zone is modified or deleted in Google Cloud.
references:
    - https://cloud.google.com/dns/docs/reference/v1/managedZones
author: Austin Songer @austinsonger
date: 2021-08-15
modified: 2022-10-09
tags:
    - attack.impact
logsource:
    product: gcp
    service: gcp.audit
detection:
    selection:
        gcp.audit.method_name:
            - Dns.ManagedZones.Delete
            - Dns.ManagedZones.Update
            - Dns.ManagedZones.Patch
    condition: selection
falsepositives:
    - Unknown
level: medium
