<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/web/proxy_generic/proxy_ua_base64_encoded.yml -->
title: Suspicious Base64 Encoded User-Agent
id: d443095b-a221-4957-a2c4-cd1756c9b747
related:
    - id: 894a8613-cf12-48b3-8e57-9085f54aa0c3
      type: derived
status: test
description: Detects suspicious encoded User-Agent strings, as seen used by some malware.
references:
    - https://deviceatlas.com/blog/list-of-user-agent-strings#desktop
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-04
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        c-useragent|startswith:
            - 'Q2hyb21l' # Chrome Encoded with offset to not include padding
            - 'QXBwbGVXZWJLaX' # AppleWebKit Encoded with offset to not include padding
            - 'RGFsdmlr' # Dalvik Encoded with offset to not include padding
            - 'TW96aWxsY'  # Mozilla Encoded with offset to not include padding (as used by YamaBot)
    condition: selection
falsepositives:
    - Unknown
level: medium
