<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/builtin/lnx_susp_jexboss.yml -->
title: JexBoss Command Sequence
id: 8ec2c8b4-557a-4121-b87c-5dfb3a602fae
status: test
description: Detects suspicious command sequence that JexBoss
references:
    - https://www.us-cert.gov/ncas/analysis-reports/AR18-312A
author: Florian Roth (Nextron Systems)
date: 2017-08-24
modified: 2025-11-22
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    product: linux
detection:
    keywords:
        '|all':
            - 'bash -c /bin/bash'
            - '&/dev/tcp/'
    condition: keywords
falsepositives:
    - Unknown
level: high
