<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2024/TA/DPRK/dns_query_win_apt_dprk_malicious_domains.yml -->
title: DPRK Threat Actor - C2 Communication DNS Indicators
id: 4d16c9a6-4362-4863-9940-1dee35f1d70f
status: test
description: Detects DNS queries for C2 domains used by DPRK Threat actors.
references:
    - https://www.verfassungsschutz.de/SharedDocs/publikationen/DE/cyberabwehr/2024-02-19-joint-cyber-security-advisory-englisch.pdf?__blob=publicationFile&v=2
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-02-20
tags:
    - attack.command-and-control
    - detection.emerging-threats
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName:
            - 'connection.lockscreen.kro.kr'
            - 'updating.dothome.co.kr'
    condition: selection
falsepositives:
    - Unlikely
level: high
