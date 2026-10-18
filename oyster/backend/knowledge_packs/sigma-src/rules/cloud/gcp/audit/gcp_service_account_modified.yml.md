<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/gcp/audit/gcp_service_account_modified.yml -->
title: Google Cloud Service Account Modified
id: 6b67c12e-5e40-47c6-b3b0-1e6b571184cc
status: test
description: Identifies when a service account is modified in Google Cloud.
references:
    - https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts
author: Austin Songer @austinsonger
date: 2021-08-14
modified: 2022-10-09
tags:
    - attack.impact
logsource:
    product: gcp
    service: gcp.audit
detection:
    selection:
        gcp.audit.method_name|endswith:
            - .serviceAccounts.patch
            - .serviceAccounts.create
            - .serviceAccounts.update
            - .serviceAccounts.enable
            - .serviceAccounts.undelete
    condition: selection
falsepositives:
    - Service Account being modified may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Service Account modified from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium
