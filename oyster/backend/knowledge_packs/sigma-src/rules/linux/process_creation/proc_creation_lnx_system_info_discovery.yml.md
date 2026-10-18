<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_system_info_discovery.yml -->
title: System Information Discovery
id: 42df45e7-e6e9-43b5-8f26-bec5b39cc239
status: stable
description: Detects system information discovery commands
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md
author: Ömer Günal, oscd.community
date: 2020-10-08
modified: 2021-09-14
tags:
    - attack.discovery
    - attack.t1082
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/uname'
            - '/hostname'
            - '/uptime'
            - '/lspci'
            - '/dmidecode'
            - '/lscpu'
            - '/lsmod'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: informational
