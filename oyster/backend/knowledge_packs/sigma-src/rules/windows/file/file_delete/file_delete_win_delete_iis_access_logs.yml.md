<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_delete/file_delete_win_delete_iis_access_logs.yml -->
title: IIS WebServer Access Logs Deleted
id: 3eb8c339-a765-48cc-a150-4364c04652bf
related:
    - id: 0649be4a-aeb0-45b0-b89e-7f1668f6d9c0
      type: similar
status: test
description: Detects the deletion of IIS WebServer access logs which may indicate an attempt to destroy forensic evidence
references:
    - https://www.elastic.co/guide/en/security/current/webserver-access-logs-deleted.html
author: Tim Rauch (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-16
modified: 2023-02-15
tags:
    - attack.stealth
    - attack.t1070
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|contains: '\inetpub\logs\LogFiles\'
        TargetFilename|endswith: '.log'
    condition: selection
falsepositives:
    - During uninstallation of the IIS service
    - During log rotation
level: medium
