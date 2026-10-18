<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/bitbucket/audit/bitbucket_audit_secret_scanning_exempt_repository_detected.yml -->
title: Bitbucket Secret Scanning Exempt Repository Added
id: b91e8d5e-0033-44fe-973f-b730316f23a1
status: test
description: Detects when a repository is exempted from secret scanning feature.
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
        auditType.category: 'Repositories'
        auditType.action: 'Secret scanning exempt repository added'
    condition: selection
falsepositives:
    - Legitimate user activity.
level: high
