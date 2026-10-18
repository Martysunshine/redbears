<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/aws/cloudtrail/aws_rds_public_db_restore.yml -->
title: Restore Public AWS RDS Instance
id: c3f265c7-ff03-4056-8ab2-d486227b4599
status: test
description: Detects the recovery of a new public database instance from a snapshot. It may be a part of data exfiltration.
references:
    - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/rds__explore_snapshots/main.py
author: faloker
date: 2020-02-12
modified: 2022-10-09
tags:
    - attack.exfiltration
    - attack.t1020
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: rds.amazonaws.com
        responseElements.publiclyAccessible: 'true'
        eventName: RestoreDBInstanceFromDBSnapshot
    condition: selection_source
falsepositives:
    - Unknown
level: high
