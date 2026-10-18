<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/builtin/guacamole/lnx_guacamole_susp_guacamole.yml -->
title: Guacamole Two Users Sharing Session Anomaly
id: 1edd77db-0669-4fef-9598-165bda82826d
status: test
description: Detects suspicious session with two users present
references:
    - https://research.checkpoint.com/2020/apache-guacamole-rce/
author: Florian Roth (Nextron Systems)
date: 2020-07-03
modified: 2021-11-27
tags:
    - attack.credential-access
    - attack.t1212
logsource:
    product: linux
    service: guacamole
detection:
    selection:
        - '(2 users now present)'
    condition: selection
falsepositives:
    - Unknown
level: high
