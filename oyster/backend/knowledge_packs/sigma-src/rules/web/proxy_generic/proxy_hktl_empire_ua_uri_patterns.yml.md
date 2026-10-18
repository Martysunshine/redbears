<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/web/proxy_generic/proxy_hktl_empire_ua_uri_patterns.yml -->
title: HackTool - Empire UserAgent URI Combo
id: b923f7d6-ac89-4a50-a71a-89fb846b4aa8
status: test
description: Detects user agent and URI paths used by empire agents
references:
    - https://github.com/BC-SECURITY/Empire
author: Florian Roth (Nextron Systems)
date: 2020-07-13
modified: 2024-02-26
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        c-useragent: 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
        cs-uri:
            - '/admin/get.php'
            - '/news.php'
            - '/login/process.php'
        cs-method: 'POST'
    condition: selection
falsepositives:
    - Valid requests with this exact user agent to server scripts of the defined names
level: high
