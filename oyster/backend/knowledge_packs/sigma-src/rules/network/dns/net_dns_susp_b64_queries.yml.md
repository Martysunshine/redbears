<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/network/dns/net_dns_susp_b64_queries.yml -->
title: Suspicious DNS Query with B64 Encoded String
id: 4153a907-2451-4e4f-a578-c52bb6881432
status: test
description: Detects suspicious DNS queries using base64 encoding
references:
    - https://github.com/krmaxwell/dns-exfiltration
author: Florian Roth (Nextron Systems)
date: 2018-05-10
modified: 2022-10-09
tags:
    - attack.exfiltration
    - attack.t1048.003
    - attack.command-and-control
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection:
        query|contains: '==.'
    condition: selection
falsepositives:
    - Unknown
level: medium
