<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/bitbucket/audit/bitbucket_audit_user_details_export_attempt_detected.yml -->
title: Bitbucket User Details Export Attempt Detected
id: 5259cbf2-0a75-48bf-b57a-c54d6fabaef3
status: test
description: Detects user data export activity.
references:
    - https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
    - https://support.atlassian.com/security-and-access-policies/docs/export-user-accounts
author: Muhammad Faisal (@faisalusuf)
date: 2024-02-25
tags:
    - attack.collection
    - attack.reconnaissance
    - attack.discovery
    - attack.t1213
    - attack.t1082
    - attack.t1591.004
logsource:
    product: bitbucket
    service: audit
    definition: 'Requirements: "Advance" log level is required to receive these audit events.'
detection:
    selection:
        auditType.category: 'Users and groups'
        auditType.action:
            - 'User permissions export failed'
            - 'User permissions export started'
            - 'User permissions exported'
    condition: selection
falsepositives:
    - Legitimate user activity.
level: medium
