<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/bitbucket/audit/bitbucket_audit_unauthorized_access_detected.yml -->
title: Bitbucket Unauthorized Access To A Resource
id: 7215374a-de4f-4b33-8ba5-70804c9251d3
status: test
description: Detects unauthorized access attempts to a resource.
references:
    - https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
author: Muhammad Faisal (@faisalusuf)
date: 2024-02-25
tags:
    - attack.resource-development
    - attack.t1586
logsource:
    product: bitbucket
    service: audit
    definition: 'Requirements: "Advance" log level is required to receive these audit events.'
detection:
    selection:
        auditType.category: 'Security'
        auditType.action: 'Unauthorized access to a resource'
    condition: selection
falsepositives:
    - Access attempts to non-existent repositories or due to outdated plugins. Usually "Anonymous" user is reported in the "author.name" field in most cases.
level: critical
