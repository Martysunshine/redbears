<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/aws/cloudtrail/aws_config_disable_recording.yml -->
title: AWS Config Disabling Channel/Recorder
id: 07330162-dba1-4746-8121-a9647d49d297
status: test
description: Detects AWS Config Service disabling
references:
    - https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-log-files-for-aws-config.html
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
    selection:
        eventSource: 'config.amazonaws.com'
        eventName:
            - 'DeleteDeliveryChannel'
            - 'StopConfigurationRecorder'
    condition: selection
falsepositives:
    - Valid change in AWS Config Service
level: high
