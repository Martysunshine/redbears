<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml -->
title: AWS Snapshot Backup Exfiltration
id: abae8fec-57bd-4f87-aff6-6e3db989843d
status: test
description: Detects the modification of an EC2 snapshot's permissions to enable access from another account
references:
    - https://www.justice.gov/file/1080281/download
author: Darin Smith
date: 2021-05-17
modified: 2021-08-19
tags:
    - attack.exfiltration
    - attack.t1537
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: ec2.amazonaws.com
        eventName: ModifySnapshotAttribute
    condition: selection_source
falsepositives:
    - Valid change to a snapshot's permissions
level: medium
