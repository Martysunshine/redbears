<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/aws/cloudtrail/aws_iam_s3browser_templated_s3_bucket_policy_creation.yml -->
title: AWS IAM S3Browser Templated S3 Bucket Policy Creation
id: db014773-7375-4f4e-b83b-133337c0ffee
status: test
description: Detects S3 browser utility creating Inline IAM policy containing default S3 bucket name placeholder value of "<YOUR-BUCKET-NAME>".
references:
    - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
author: daniel.bohannon@permiso.io (@danielhbohannon)
date: 2023-05-17
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.009
    - attack.persistence
    - attack.initial-access
    - attack.privilege-escalation
    - attack.t1078.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: iam.amazonaws.com
        eventName: PutUserPolicy
        userAgent|contains: 'S3 Browser'
        requestParameters|contains|all:
            - '"arn:aws:s3:::<YOUR-BUCKET-NAME>/*"'
            - '"s3:GetObject"'
            - '"Allow"'
    condition: selection
falsepositives:
    - Valid usage of S3 browser with accidental creation of default Inline IAM policy without changing default S3 bucket name placeholder value
level: high
