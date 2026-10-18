<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_system_network_connections_discovery.yml -->
title: System Network Connections Discovery - Linux
id: 4c519226-f0cd-4471-bd2f-6fbb2bb68a79
status: test
description: Detects usage of system utilities to discover system network connections
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md
author: Daniil Yugoslavskiy, oscd.community
date: 2020-10-19
modified: 2023-01-17
tags:
    - attack.discovery
    - attack.t1049
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/who'
            - '/w'
            - '/last'
            - '/lsof'
            - '/netstat'
    filter_landscape_sysinfo:
        ParentCommandLine|contains: '/usr/bin/landscape-sysinfo'
        Image|endswith: '/who'
    condition: selection and not 1 of filter_*
falsepositives:
    - Legitimate activities
level: low
