<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/linux/process_creation/proc_creation_lnx_susp_process_termination_via_kill.yml -->
title: Terminate Linux Process Via Kill
id: 64c41342-6b27-523b-5d3f-c265f3efcdb3
status: test
description: Detects usage of command line tools such as "kill", "pkill" or "killall" to terminate or signal a running process.
references:
    - https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html
    - https://www.cyberciti.biz/faq/how-force-kill-process-linux/
    - https://www.geeksforgeeks.org/how-to-kill-processes-on-the-linux-desktop-with-xkill/
author: Tuan Le (NCSGroup)
date: 2023-03-16
modified: 2024-12-12
tags:
    - attack.defense-impairment
    - attack.t1685
    - detection.threat-hunting
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/kill'
            - '/killall'
            - '/pkill'
            - '/xkill'
    condition: selection
falsepositives:
    - Unknown
level: medium
