<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/github/audit/github_ssh_certificate_config_changed.yml -->
title: Github SSH Certificate Configuration Changed
id: 2f575940-d85e-4ddc-af13-17dad6f1a0ef
status: test
description: Detects when changes are made to the SSH certificate configuration of the organization.
references:
    - https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-git-access-to-your-organizations-repositories/about-ssh-certificate-authorities
    - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise#ssh_certificate_authority
author: Romain Gaillard (@romain-gaillard)
date: 2024-07-29
tags:
    - attack.initial-access
    - attack.persistence
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1078.004
logsource:
    product: github
    service: audit
    definition: 'Requirements: The audit log streaming feature must be enabled to be able to receive such logs. You can enable following the documentation here: https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-audit-log-streaming'
detection:
    selection:
        action:
            - 'ssh_certificate_authority.create' # An SSH certificate authority for an organization or enterprise was created.
            - 'ssh_certificate_requirement.disable' # The requirement for members to use SSH certificates to access an organization resources was disabled.
    condition: selection
falsepositives:
    - Allowed administrative activities.
level: medium
