<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/dns_client/win_dns_client_mal_cobaltstrike.yml -->
title: Suspicious Cobalt Strike DNS Beaconing - DNS Client
id: 0d18728b-f5bf-4381-9dcf-915539fff6c2
related:
    - id: f356a9c4-effd-4608-bbf8-408afd5cd006
      type: similar
status: test
description: Detects a program that invoked suspicious DNS queries known from Cobalt Strike beacons
references:
    - https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
    - https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-16
tags:
    - attack.t1071.004
    - attack.command-and-control
logsource:
    product: windows
    service: dns-client
    definition: 'Requirements: Microsoft-Windows-DNS Client Events/Operational Event Log must be enabled/collected in order to receive the events.'
detection:
    selection_eid:
        EventID: 3008
    selection_query_1:
        QueryName|startswith:
            - 'aaa.stage.'
            - 'post.1'
    selection_query_2:
        QueryName|contains: '.stage.123456.'
    condition: selection_eid and 1 of selection_query_*
falsepositives:
    - Unknown
level: critical
