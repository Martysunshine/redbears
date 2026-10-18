<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/opencanary/opencanary_vnc_connection_attempt.yml -->
title: OpenCanary - VNC Connection Attempt
id: 9db5446c-b44a-4291-8b89-fcab5609c3b3
status: test
description: Detects instances where a VNC service on an OpenCanary node has had a connection attempt.
references:
    - https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
    - https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52
author: Security Onion Solutions
date: 2024-03-08
tags:
    - attack.lateral-movement
    - attack.t1021
logsource:
    category: application
    product: opencanary
detection:
    selection:
        logtype: 12001
    condition: selection
falsepositives:
    - Unlikely
level: high
