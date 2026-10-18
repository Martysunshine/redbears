<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/opencanary/opencanary_redis_command.yml -->
title: OpenCanary - REDIS Action Command Attempt
id: 547dfc53-ebf6-4afe-8d2e-793d9574975d
status: test
description: Detects instances where a REDIS service on an OpenCanary node has had an action command attempted.
references:
    - https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
    - https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52
author: Security Onion Solutions
date: 2024-03-08
tags:
    - attack.credential-access
    - attack.collection
    - attack.t1003
    - attack.t1213
logsource:
    category: application
    product: opencanary
detection:
    selection:
        logtype: 17001
    condition: selection
falsepositives:
    - Unlikely
level: high
