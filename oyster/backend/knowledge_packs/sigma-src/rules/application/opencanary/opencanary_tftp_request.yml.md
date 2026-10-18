<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/opencanary/opencanary_tftp_request.yml -->
title: OpenCanary - TFTP Request
id: b4e6b016-a2ac-4759-ad85-8000b300d61e
status: test
description: Detects instances where a TFTP service on an OpenCanary node has had a request.
references:
    - https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
    - https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52
author: Security Onion Solutions
date: 2024-03-08
tags:
    - attack.exfiltration
    - attack.t1041
logsource:
    category: application
    product: opencanary
detection:
    selection:
        logtype: 10001
    condition: selection
falsepositives:
    - Unlikely
level: high
