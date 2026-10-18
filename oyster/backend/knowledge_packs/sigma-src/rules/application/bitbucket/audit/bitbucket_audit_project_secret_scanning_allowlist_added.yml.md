<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/bitbucket/audit/bitbucket_audit_project_secret_scanning_allowlist_added.yml -->
title: Bitbucket Project Secret Scanning Allowlist Added
id: 42ccce6d-7bd3-4930-95cd-e4d83fa94a30
status: test
description: Detects when a secret scanning allowlist rule is added for projects.
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
        auditType.category: 'Projects'
        auditType.action: 'Project secret scanning allowlist rule added'
    condition: selection
falsepositives:
    - Legitimate user activity.
level: low
