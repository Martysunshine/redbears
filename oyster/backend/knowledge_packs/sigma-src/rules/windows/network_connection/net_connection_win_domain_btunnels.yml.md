<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/network_connection/net_connection_win_domain_btunnels.yml -->
title: Network Connection Initiated To BTunnels Domains
id: 9e02c8ec-02b9-43e8-81eb-34a475ba7965
status: test
description: |
    Detects network connections to BTunnels domains initiated by a process on the system.
    Attackers can abuse that feature to establish a reverse shell or persistence on a machine.
references:
    - https://defr0ggy.github.io/research/Utilizing-BTunnel-For-Data-Exfiltration/
author: Kamran Saifullah
date: 2024-09-13
tags:
    - attack.exfiltration
    - attack.command-and-control
    - attack.t1567
    - attack.t1572
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        DestinationHostname|endswith: '.btunnel.co.in'
    condition: selection
falsepositives:
    - Legitimate use of BTunnels will also trigger this.
level: medium
