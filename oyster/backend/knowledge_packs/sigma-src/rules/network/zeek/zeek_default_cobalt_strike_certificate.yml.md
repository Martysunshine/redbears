<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/network/zeek/zeek_default_cobalt_strike_certificate.yml -->
title: Default Cobalt Strike Certificate
id: 7100f7e3-92ce-4584-b7b7-01b40d3d4118
status: test
description: Detects the presence of default Cobalt Strike certificate in the HTTPS traffic
references:
    - https://sergiusechel.medium.com/improving-the-network-based-detection-of-cobalt-strike-c2-servers-in-the-wild-while-reducing-the-6964205f6468
author: Bhabesh Raj
date: 2021-06-23
modified: 2022-10-09
tags:
    - attack.command-and-control
    - attack.s0154
logsource:
    product: zeek
    service: x509
detection:
    selection:
        certificate.serial: 8BB00EE
    condition: selection
falsepositives:
    - Unknown
level: high
