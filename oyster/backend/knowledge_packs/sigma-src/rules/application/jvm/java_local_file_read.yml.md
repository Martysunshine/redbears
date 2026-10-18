<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/jvm/java_local_file_read.yml -->
title: Potential Local File Read Vulnerability In JVM Based Application
id: e032f5bc-4563-4096-ae3b-064bab588685
status: test
description: |
    Detects potential local file read vulnerability in JVM based apps.
    If the exceptions are caused due to user input and contain path traversal payloads then it's a red flag.
references:
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: Moti Harmats
date: 2023-02-11
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: application
    product: jvm
    definition: 'Requirements: application error logs must be collected (with LOG_LEVEL=ERROR and above)'
detection:
    keywords_local_file_read:
        '|all':
            - 'FileNotFoundException'
            - '/../../..'
    condition: keywords_local_file_read
falsepositives:
    - Application bugs
level: high
