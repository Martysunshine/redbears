<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/github/audit/github_push_protection_bypass_detected.yml -->
title: Github Push Protection Bypass Detected
id: 02cf536a-cf21-4876-8842-4159c8aee3cc
status: test
description: Detects when a user bypasses the push protection on a secret detected by secret scanning.
references:
    - https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/push-protection-for-repositories-and-organizations
    - https://thehackernews.com/2024/03/github-rolls-out-default-secret.html
author: Muhammad Faisal (@faisalusuf)
date: 2024-03-07
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: github
    service: audit
    definition: 'Requirements: The audit log streaming feature must be enabled to be able to receive such logs. You can enable following the documentation here: https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-audit-log-streaming'
detection:
    selection:
        action|contains: 'secret_scanning_push_protection.bypass'
    condition: selection
falsepositives:
    - Allowed administrative activities.
level: low
