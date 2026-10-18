<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/network/cisco/aaa/cisco_cli_modify_config.yml -->
title: Cisco Modify Configuration
id: 671ffc77-50a7-464f-9e3d-9ea2b493b26b
status: test
description: Modifications to a config that will serve an adversary's impacts or persistence
author: Austin Clark
date: 2019-08-12
modified: 2025-04-28
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.impact
    - attack.t1490
    - attack.t1505
    - attack.t1565.002
    - attack.t1053
logsource:
    product: cisco
    service: aaa
detection:
    keywords:
        - 'ip http server'
        - 'ip https server'
        - 'kron policy-list'
        - 'kron occurrence'
        - 'policy-list'
        - 'access-list'
        - 'ip access-group'
        - 'archive maximum'
        - 'ntp server'
    condition: keywords
falsepositives:
    - Legitimate administrators may run these commands
level: medium
