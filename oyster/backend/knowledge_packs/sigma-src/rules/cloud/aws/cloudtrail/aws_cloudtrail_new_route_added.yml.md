<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/aws/cloudtrail/aws_cloudtrail_new_route_added.yml -->
title: New Network Route Added
id: c803b2ce-c4a2-4836-beae-b112010390b1
status: test
description: |
    Detects the addition of a new network route to a route table in AWS.
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
        eventName: 'CreateRoute'
    condition: selection
falsepositives:
    - New VPC Creation requiring setup of a new route table
    - New subnets added requiring routing setup
level: medium
