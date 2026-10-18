<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/web/proxy_generic/proxy_ua_rclone.yml -->
title: Rclone Activity via Proxy
id: 2c03648b-e081-41a5-b9fb-7d854a915091
status: test
description: Detects the use of rclone, a command-line program to manage files on cloud storage, via its default user-agent string
references:
    - https://rclone.org/
    - https://www.kroll.com/en/insights/publications/cyber/new-m365-business-email-compromise-attacks-with-rclone
author: Janantha Marasinghe
date: 2022-10-18
tags:
    - attack.exfiltration
    - attack.t1567.002
logsource:
    category: proxy
detection:
    selection:
        c-useragent|startswith: 'rclone/v'
    condition: selection
falsepositives:
    - Valid requests with this exact user agent to that is used by legitimate scripts or sysadmin operations
level: medium
