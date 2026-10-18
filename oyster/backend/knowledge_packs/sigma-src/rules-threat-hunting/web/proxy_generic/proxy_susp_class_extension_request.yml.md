<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/web/proxy_generic/proxy_susp_class_extension_request.yml -->
title: .Class Extension URI Ending Request
id: 53c15703-b04c-42bb-9055-1937ddfb3392
status: test
description: |
    Detects requests to URI ending with the ".class" extension in proxy logs.
    This could rules can be used to hunt for potential downloads of Java classes as seen for example in Log4shell exploitation attacks against Log4j.
references:
    - https://web.archive.org/web/20231230220738/https://www.lunasec.io/docs/blog/log4j-zero-day/
author: Andreas Hunkeler (@Karneades)
date: 2021-12-21
modified: 2024-02-26
tags:
    - attack.initial-access
    - detection.threat-hunting
logsource:
    category: proxy
detection:
    selection:
        c-uri|endswith: '.class'
    condition: selection
falsepositives:
    - Unknown
level: medium
