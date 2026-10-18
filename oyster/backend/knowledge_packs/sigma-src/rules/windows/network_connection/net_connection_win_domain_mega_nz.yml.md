<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/network_connection/net_connection_win_domain_mega_nz.yml -->
title: Network Connection Initiated To Mega.nz
id: fdeebdf0-9f3f-4d08-84a6-4c4d13e39fe4
status: test
description: |
    Detects a network connection initiated by a binary to "api.mega.co.nz".
    Attackers were seen abusing file sharing websites similar to "mega.nz" in order to upload/download additional payloads.
references:
    - https://megatools.megous.com/
    - https://www.mandiant.com/resources/russian-targeting-gov-business
author: Florian Roth (Nextron Systems)
date: 2021-12-06
modified: 2024-05-31
tags:
    - attack.exfiltration
    - attack.t1567.002
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        DestinationHostname|endswith:
            - 'mega.co.nz'
            - 'mega.nz'
    condition: selection
falsepositives:
    - Legitimate MEGA installers and utilities are expected to communicate with this domain. Exclude hosts that are known to be allowed to use this tool.
level: low
