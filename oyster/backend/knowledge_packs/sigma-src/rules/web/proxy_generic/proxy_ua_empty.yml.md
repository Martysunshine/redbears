<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/web/proxy_generic/proxy_ua_empty.yml -->
title: HTTP Request With Empty User Agent
id: 21e44d78-95e7-421b-a464-ffd8395659c4
status: test
description: |
    Detects a potentially suspicious empty user agent strings in proxy log.
    Could potentially indicate an uncommon request method.
references:
    - https://twitter.com/Carlos_Perez/status/883455096645931008
author: Florian Roth (Nextron Systems)
date: 2017-07-08
modified: 2021-11-27
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
      # Empty string - as used by Powershell's (New-Object Net.WebClient).DownloadString
        c-useragent: ''
    condition: selection
falsepositives:
    - Unknown
level: medium
