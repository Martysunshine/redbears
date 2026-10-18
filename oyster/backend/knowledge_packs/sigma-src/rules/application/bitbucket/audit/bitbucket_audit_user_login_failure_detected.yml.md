<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/bitbucket/audit/bitbucket_audit_user_login_failure_detected.yml -->
title: Bitbucket User Login Failure
id: 70ed1d26-0050-4b38-a599-92c53d57d45a
status: test
description: |
    Detects user authentication failure events.
    Please note that this rule can be noisy and it is recommended to use with correlation based on "author.name" field.
references:
    - https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
author: Muhammad Faisal (@faisalusuf)
date: 2024-02-25
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.initial-access
    - attack.credential-access
    - attack.stealth
    - attack.t1078.004
    - attack.t1110
logsource:
    product: bitbucket
    service: audit
    definition: 'Requirements: "Advance" log level is required to receive these audit events.'
detection:
    selection:
        auditType.category: 'Authentication'
        auditType.action: 'User login failed'
    condition: selection
falsepositives:
    - Legitimate user wrong password attempts.
level: medium
