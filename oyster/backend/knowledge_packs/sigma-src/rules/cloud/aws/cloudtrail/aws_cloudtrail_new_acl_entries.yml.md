<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/aws/cloudtrail/aws_cloudtrail_new_acl_entries.yml -->
title: New Network ACL Entry Added
id: e1f7febb-7b94-4234-b5c6-00fb8500f5dd
status: test
description: |
    Detects that network ACL entries have been added to a route table which could indicate that new attack vectors have been opened up in the AWS account.
references:
    - https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/
author: jamesc-grafana
date: 2024-07-11
tags:
    - attack.defense-impairment
    - attack.t1686.001
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'ec2.amazonaws.com'
        eventName: 'CreateNetworkAclEntry'
    condition: selection
falsepositives:
    - Legitimate use of ACLs to enable customer and staff access from the public internet into a public VPC
level: low
