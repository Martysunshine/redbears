<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_federation_modified.yml -->
title: Azure Domain Federation Settings Modified
id: 352a54e1-74ba-4929-9d47-8193d67aba1e
status: test
description: Identifies when an user or application modified the federation settings on the domain.
references:
    - https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-monitor-federation-changes
author: Austin Songer
date: 2021-09-06
modified: 2022-06-08
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.initial-access
    - attack.stealth
    - attack.t1078
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        ActivityDisplayName: Set federation settings on domain
    condition: selection
falsepositives:
    - Federation Settings being modified or deleted may be performed by a system administrator.
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Federation Settings modified from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

level: medium
