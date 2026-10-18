<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/bitbucket/audit/bitbucket_audit_global_ssh_settings_change_detected.yml -->
title: Bitbucket Global SSH Settings Changed
id: 16ab6143-510a-44e2-a615-bdb80b8317fc
status: test
description: Detects Bitbucket global SSH access configuration changes.
references:
    - https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
    - https://confluence.atlassian.com/bitbucketserver/enable-ssh-access-to-git-repositories-776640358.html
author: Muhammad Faisal (@faisalusuf)
date: 2024-02-25
tags:
    - attack.lateral-movement
    - attack.defense-impairment
    - attack.t1685
    - attack.t1021.004
logsource:
    product: bitbucket
    service: audit
    definition: 'Requirements: "Advance" log level is required to receive these audit events.'
detection:
    selection:
        auditType.category: 'Global administration'
        auditType.action: 'SSH settings changed'
    condition: selection
falsepositives:
    - Legitimate user activity.
level: medium
