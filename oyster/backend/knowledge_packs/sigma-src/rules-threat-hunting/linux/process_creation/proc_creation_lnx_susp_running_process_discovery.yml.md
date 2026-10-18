<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/linux/process_creation/proc_creation_lnx_susp_running_process_discovery.yml -->
title: Process Discovery
id: 4e2f5868-08d4-413d-899f-dc2f1508627b
status: stable
description: |
  Detects process discovery commands. Adversaries may attempt to get information about running processes on a system.
  Information obtained could be used to gain an understanding of common software/applications running on systems within the network
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1057/T1057.md
    - https://www.cyberciti.biz/faq/show-all-running-processes-in-linux/
author: Ömer Günal, oscd.community, CheraaghiMilad
date: 2020-10-06
modified: 2022-07-07
tags:
    - attack.discovery
    - attack.t1057
    - detection.threat-hunting
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/atop'
            - '/htop'
            - '/pgrep'
            - '/ps'
            - '/pstree'
            - '/top'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: low
