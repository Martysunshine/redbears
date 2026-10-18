<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/opencanary/opencanary_httpproxy_login_attempt.yml -->
title: OpenCanary - HTTPPROXY Login Attempt
id: 5498fc09-adc6-4804-b9d9-5cca1f0b8760
status: test
description: |
    Detects instances where an HTTPPROXY service on an OpenCanary node has had an attempt to proxy another page.
references:
    - https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
    - https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52
author: Security Onion Solutions
date: 2024-03-08
tags:
    - attack.initial-access
    - attack.command-and-control
    - attack.t1090
logsource:
    category: application
    product: opencanary
detection:
    selection:
        logtype: 7001
    condition: selection
falsepositives:
    - Unlikely
level: high
