<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/web/webserver_generic/web_source_code_enumeration.yml -->
title: Source Code Enumeration Detection by Keyword
id: 953d460b-f810-420a-97a2-cfca4c98e602
status: test
description: Detects source code enumeration that use GET requests by keyword searches in URL strings
references:
    - https://pentester.land/tutorials/2018/10/25/source-code-disclosure-via-exposed-git-folder.html
    - https://medium.com/@logicbomb_1/bugbounty-how-i-was-able-to-download-the-source-code-of-indias-largest-telecom-service-52cf5c5640a1
author: James Ahearn
date: 2019-06-08
modified: 2022-10-05
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: webserver
detection:
    keywords:
        - '.git/'
    condition: keywords
falsepositives:
    - Unknown
level: medium
