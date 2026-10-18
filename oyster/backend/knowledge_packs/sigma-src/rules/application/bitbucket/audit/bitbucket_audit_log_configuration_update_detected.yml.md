<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/bitbucket/audit/bitbucket_audit_log_configuration_update_detected.yml -->
title: Bitbucket Audit Log Configuration Updated
id: 6aa12161-235a-4dfb-9c74-fe08df8d8da1
status: test
description: Detects changes to the bitbucket audit log configuration.
references:
    - https://confluence.atlassian.com/bitbucketserver/view-and-configure-the-audit-log-776640417.html
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
        auditType.category: 'Auditing'
        auditType.action: 'Audit log configuration updated'
    condition: selection
falsepositives:
    - Legitimate user activity.
level: medium
