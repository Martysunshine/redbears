<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/dns_query/dns_query_win_cloudflared_communication.yml -->
title: Cloudflared Tunnels Related DNS Requests
id: a1d9eec5-33b2-4177-8d24-27fe754d0812
related:
    - id: 7cd1dcdc-6edf-4896-86dc-d1f19ad64903
      type: similar
status: test
description: |
    Detects DNS requests to Cloudflared tunnels domains.
    Attackers can abuse that feature to establish a reverse shell or persistence on a machine.
references:
    - https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-12-20
tags:
    - attack.command-and-control
    - attack.t1071.001
    - attack.t1572
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - '.v2.argotunnel.com'
            - 'protocol-v2.argotunnel.com'
            - 'trycloudflare.com'
            - 'update.argotunnel.com'
    condition: selection
falsepositives:
    - Legitimate use of cloudflare tunnels will also trigger this.
level: medium
