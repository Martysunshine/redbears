<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/opencanary/opencanary_mysql_login_attempt.yml -->
title: OpenCanary - MySQL Login Attempt
id: e7d79a1b-25ed-4956-bd56-bd344fa8fd06
status: test
description: Detects instances where a MySQL service on an OpenCanary node has had a login attempt.
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
        logtype: 8001
    condition: selection
falsepositives:
    - Unlikely
level: high
