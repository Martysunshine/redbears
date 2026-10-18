<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/bitbucket/audit/bitbucket_audit_full_data_export_triggered.yml -->
title: Bitbucket Full Data Export Triggered
id: 195e1b9d-bfc2-4ffa-ab4e-35aef69815f8
status: test
description: Detects when full data export is attempted.
references:
    - https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
    - https://confluence.atlassian.com/adminjiraserver0811/importing-and-exporting-data-1019391889.html
author: Muhammad Faisal (@faisalusuf)
date: 2024-02-25
tags:
    - attack.collection
    - attack.t1213.003
logsource:
    product: bitbucket
    service: audit
    definition: 'Requirements: "Advance" log level is required to receive these audit events.'
detection:
    selection:
        auditType.category: 'Data pipeline'
        auditType.action: 'Full data export triggered'
    condition: selection
falsepositives:
    - Legitimate user activity.
level: high
