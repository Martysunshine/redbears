<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml -->
title: Disabling Security Tools - Builtin
id: 49f5dfc1-f92e-4d34-96fa-feba3f6acf36
related:
    - id: e3a8a052-111f-4606-9aee-f28ebeb76776
      type: derived
status: test
description: Detects disabling security tools
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md
author: Ömer Günal, Alejandro Ortuno, oscd.community
date: 2020-06-17
modified: 2022-11-26
tags:
    - attack.defense-impairment
    - attack.t1686
logsource:
    product: linux
    service: syslog
detection:
    keywords:
        - 'stopping iptables'
        - 'stopping ip6tables'
        - 'stopping firewalld'
        - 'stopping cbdaemon'
        - 'stopping falcon-sensor'
    condition: keywords
falsepositives:
    - Legitimate administration activities
level: medium
