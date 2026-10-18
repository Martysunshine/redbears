<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/dns_server/win_dns_server_failed_dns_zone_transfer.yml -->
title: Failed DNS Zone Transfer
id: 6d444368-6da1-43fe-b2fc-44202430480e
status: test
description: Detects when a DNS zone transfer failed.
references:
    - https://kb.eventtracker.com/evtpass/evtpages/EventId_6004_Microsoft-Windows-DNS-Server-Service_65410.asp
author: Zach Mathis
date: 2023-05-24
tags:
    - attack.reconnaissance
    - attack.t1590.002
logsource:
    product: windows
    service: dns-server
detection:
    selection:
        EventID: 6004 # The DNS server received a zone transfer request from %1 for a non-existent or non-authoritative zone %2.
    condition: selection
falsepositives:
    - Unlikely
level: medium
