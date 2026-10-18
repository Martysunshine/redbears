<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/bitbucket/audit/bitbucket_audit_unauthorized_full_data_export_triggered.yml -->
title: Bitbucket Unauthorized Full Data Export Triggered
id: 34d81081-03c9-4a7f-91c9-5e46af625cde
status: test
description: Detects when full data export is attempted an unauthorized user.
references:
    - https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
    - https://confluence.atlassian.com/bitbucketserver/secret-scanning-1157471613.html
author: Muhammad Faisal (@faisalusuf)
date: 2024-02-25
tags:
    - attack.collection
    - attack.resource-development
    - attack.t1213.003
    - attack.t1586
logsource:
    product: bitbucket
    service: audit
    definition: 'Requirements: "Advance" log level is required to receive these audit events.'
detection:
    selection:
        auditType.category: 'Data pipeline'
        auditType.action: 'Unauthorized full data export triggered'
    condition: selection
falsepositives:
    - Unlikely
level: critical
