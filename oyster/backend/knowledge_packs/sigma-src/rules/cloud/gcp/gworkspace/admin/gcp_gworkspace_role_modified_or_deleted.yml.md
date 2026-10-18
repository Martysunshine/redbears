<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/gcp/gworkspace/admin/gcp_gworkspace_role_modified_or_deleted.yml -->
title: Google Workspace Role Modified or Deleted
id: 6aef64e3-60c6-4782-8db3-8448759c714e
status: test
description: Detects when an a role is modified or deleted in Google Workspace.
references:
    - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
    - https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-delegated-admin-settings
author: Austin Songer
date: 2021-08-24
modified: 2023-10-11
tags:
    - attack.impact
logsource:
    product: gcp
    service: google_workspace.admin
detection:
    selection:
        eventService: admin.googleapis.com
        eventName:
            - DELETE_ROLE
            - RENAME_ROLE
            - UPDATE_ROLE
    condition: selection
falsepositives:
    - Unknown

level: medium
