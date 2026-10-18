<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/aws/cloudtrail/aws_cloudtrail_disable_logging.yml -->
title: AWS CloudTrail Important Change
id: 4db60cc0-36fb-42b7-9b58-a5b53019fb74
status: test
description: Detects disabling, deleting and updating of a Trail
references:
    - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html
author: vitaliy0x1
date: 2020-01-21
modified: 2022-10-09
tags:
    - attack.defense-impairment
    - attack.t1685.002
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: cloudtrail.amazonaws.com
        eventName:
            - StopLogging
            - UpdateTrail
            - DeleteTrail
    condition: selection_source
falsepositives:
    - Valid change in a Trail
level: medium
