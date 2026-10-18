<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/bitbucket/audit/bitbucket_audit_user_login_failure_via_ssh_detected.yml -->
title: Bitbucket User Login Failure Via SSH
id: d3f90469-fb05-42ce-b67d-0fded91bbef3
status: test
description: |
    Detects SSH user login access failures.
    Please note that this rule can be noisy and is recommended to use with correlation based on "author.name" field.
references:
    - https://confluence.atlassian.com/bitbucketserver/view-and-configure-the-audit-log-776640417.html
    - https://confluence.atlassian.com/bitbucketserver/enable-ssh-access-to-git-repositories-776640358.html
author: Muhammad Faisal (@faisalusuf)
date: 2024-02-25
tags:
    - attack.lateral-movement
    - attack.credential-access
    - attack.t1021.004
    - attack.t1110
logsource:
    product: bitbucket
    service: audit
    definition: 'Requirements: "Advance" log level is required to receive these audit events.'
detection:
    selection:
        auditType.category: 'Authentication'
        auditType.action: 'User login failed(SSH)'
    condition: selection
falsepositives:
    - Legitimate user wrong password attempts.
level: medium
