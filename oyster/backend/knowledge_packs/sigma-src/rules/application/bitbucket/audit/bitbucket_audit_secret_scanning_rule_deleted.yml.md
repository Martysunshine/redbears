<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/bitbucket/audit/bitbucket_audit_secret_scanning_rule_deleted.yml -->
title: Bitbucket Secret Scanning Rule Deleted
id: ff91e3f0-ad15-459f-9a85-1556390c138d
status: test
description: Detects when secret scanning rule is deleted for the project or repository.
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
        auditType.category:
            - 'Projects'
            - 'Repositories'
        auditType.action:
            - 'Project secret scanning rule deleted'
            - 'Repository secret scanning rule deleted'
    condition: selection
falsepositives:
    - Legitimate user activity.
level: low
