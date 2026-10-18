<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/gcp/gworkspace/admin/gcp_gworkspace_role_privilege_deleted.yml -->
title: Google Workspace Role Privilege Deleted
id: bf638ef7-4d2d-44bb-a1dc-a238252e6267
status: test
description: Detects when an a role privilege is deleted in Google Workspace.
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
        eventName: REMOVE_PRIVILEGE
    condition: selection
falsepositives:
    - Unknown

level: medium
