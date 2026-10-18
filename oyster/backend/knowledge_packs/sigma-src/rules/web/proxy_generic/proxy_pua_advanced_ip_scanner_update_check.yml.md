<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/web/proxy_generic/proxy_pua_advanced_ip_scanner_update_check.yml -->
title: PUA - Advanced IP/Port Scanner Update Check
id: 1a9bb21a-1bb5-42d7-aa05-3219c7c8f47d
status: test
description: Detect the update check performed by Advanced IP/Port Scanner utilities.
references:
    - https://www.advanced-ip-scanner.com/
    - https://www.advanced-port-scanner.com/
author: Axel Olsson
date: 2022-08-14
modified: 2024-02-15
tags:
    - attack.discovery
    - attack.reconnaissance
    - attack.t1590
logsource:
    category: proxy
detection:
    selection:
      # Example request: http://www.advanced-port-scanner.com/checkupdate.php?lng=en&ver=2-5-3680&beta=n&type=upd&rmode=p&product=aps
      # Example request2: http://www.advanced-ip-scanner.com/checkupdate.php?lng=en&ver=2-5-3499&beta=n&type=upd&rmode=p&product=aips
        c-uri|contains: '/checkupdate.php'
        c-uri-query|contains|all:
            - 'lng='
            - 'ver='
            - 'beta='
            - 'type='
            - 'rmode='
            - 'product='
    condition: selection
falsepositives:
    - Expected if you legitimately use the Advanced IP or Port Scanner utilities in your environement.
level: medium
