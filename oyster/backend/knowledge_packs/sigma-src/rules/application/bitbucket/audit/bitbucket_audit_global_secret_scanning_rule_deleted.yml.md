<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/bitbucket/audit/bitbucket_audit_global_secret_scanning_rule_deleted.yml -->
title: Bitbucket Global Secret Scanning Rule Deleted
id: e16cf0f0-ee88-4901-bd0b-4c8d13d9ee05
status: test
description: Detects Bitbucket global secret scanning rule deletion activity.
references:
    - https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
    - https://confluence.atlassian.com/bitbucketserver/secret-scanning-1157471613.html
author: Muhammad Faisal (@faisalusuf)
date: 2024-02-25
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: bitbucket
    service: audit
    definition: 'Requirements: "Basic" log level is required to receive these audit events.'
detection:
    selection:
        auditType.category: 'Global administration'
        auditType.action: 'Global secret scanning rule deleted'
    condition: selection
falsepositives:
    - Legitimate user activity.
level: medium
