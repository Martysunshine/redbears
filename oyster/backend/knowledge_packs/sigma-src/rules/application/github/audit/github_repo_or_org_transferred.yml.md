<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/github/audit/github_repo_or_org_transferred.yml -->
title: Github Repository/Organization Transferred
id: 04ad83ef-1a37-4c10-b57a-81092164bf33
status: test
description: Detects when a repository or an organization is being transferred to another location.
references:
    - https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository
    - https://docs.github.com/en/organizations/managing-organization-settings/transferring-organization-ownership
    - https://docs.github.com/en/migrations
    - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise#migration
author: Romain Gaillard (@romain-gaillard)
date: 2024-07-29
tags:
    - attack.persistence
    - attack.exfiltration
    - attack.t1020
    - attack.t1537
logsource:
    product: github
    service: audit
    definition: 'Requirements: The audit log streaming feature must be enabled to be able to receive such logs. You can enable following the documentation here: https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-audit-log-streaming'
detection:
    selection:
        action:
            - 'migration.create' # A migration file was created for transferring data from a source location (such as a GitHub.com organization or a GitHub Enterprise Server instance) to a target GitHub Enterprise Server instance.
            - 'org.transfer_outgoing' # An organization was transferred between enterprise accounts.
            - 'org.transfer' # An organization was transferred between enterprise accounts.
            - 'repo.transfer_outgoing' # A repository was transferred to another repository network.
    condition: selection
falsepositives:
    - Allowed administrative activities.
level: medium
