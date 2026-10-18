<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/dns_client/win_dns_client_put_io.yml -->
title: DNS Query To Put.io - DNS Client
id: 8b69fd42-9dad-4674-abef-7fdef43ef92a
status: test
description: Detects DNS queries for subdomains related to "Put.io" sharing website.
references:
    - https://darkatlas.io/blog/medusa-ransomware-group-opsec-failure
author: Omar Khaled (@beacon_exe)
date: 2024-08-23
tags:
    - attack.command-and-control
logsource:
    product: windows
    service: dns-client
    definition: 'Requirements: Microsoft-Windows-DNS Client Events/Operational Event Log must be enabled/collected in order to receive the events.'
detection:
    selection:
        EventID: 3008
        QueryName|contains:
            - 'api.put.io'
            - 'upload.put.io'
    condition: selection
falsepositives:
    - Legitimate DNS queries and usage of Put.io
level: medium
