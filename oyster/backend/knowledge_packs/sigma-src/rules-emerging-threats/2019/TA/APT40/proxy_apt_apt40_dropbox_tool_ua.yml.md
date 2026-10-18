<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2019/TA/APT40/proxy_apt_apt40_dropbox_tool_ua.yml -->
title: APT40 Dropbox Tool User Agent
id: 5ba715b6-71b7-44fd-8245-f66893e81b3d
status: test
description: Detects suspicious user agent string of APT40 Dropbox tool
references:
    - Internal research from Florian Roth
author: Thomas Patzke
date: 2019-11-12
modified: 2023-05-18
tags:
    - attack.command-and-control
    - attack.t1071.001
    - attack.exfiltration
    - attack.t1567.002
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        c-useragent: 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36'
        cs-host: 'api.dropbox.com'
    condition: selection
falsepositives:
    - Old browsers
level: high
