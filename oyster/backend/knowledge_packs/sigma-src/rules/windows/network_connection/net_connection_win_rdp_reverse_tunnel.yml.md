<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/network_connection/net_connection_win_rdp_reverse_tunnel.yml -->
title: RDP Over Reverse SSH Tunnel
id: 5f699bc5-5446-4a4a-a0b7-5ef2885a3eb4
status: test
description: Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389
references:
    - https://twitter.com/cyb3rops/status/1096842275437625346
author: Samir Bousseaden
date: 2019-02-16
modified: 2024-03-12
tags:
    - attack.command-and-control
    - attack.t1572
    - attack.lateral-movement
    - attack.t1021.001
    - car.2013-07-002
logsource:
    category: network_connection
    product: windows
detection:
    selection_img:
        Image|endswith: '\svchost.exe'
        Initiated: 'true'
        SourcePort: 3389
    selection_destination:
        DestinationIp|cidr:
            - '127.0.0.0/8'
            - '::1/128'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
