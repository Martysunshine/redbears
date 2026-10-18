<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/opencanary/opencanary_git_clone_request.yml -->
title: OpenCanary - GIT Clone Request
id: 4fe17521-aef3-4e6a-9d6b-4a7c8de155a8
status: test
description: Detects instances where a GIT service on an OpenCanary node has had Git Clone request.
references:
    - https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
    - https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52
author: Security Onion Solutions
date: 2024-03-08
tags:
    - attack.collection
    - attack.t1213
logsource:
    category: application
    product: opencanary
detection:
    selection:
        logtype: 16001
    condition: selection
falsepositives:
    - Unlikely
level: high
