<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2018/TA/Slingshot/proc_creation_win_apt_slingshot.yml -->
title: Defrag Deactivation
id: 958d81aa-8566-4cea-a565-59ccd4df27b0
status: test
description: Detects the deactivation and disabling of the Scheduled defragmentation task as seen by Slingshot APT group
references:
    - https://securelist.com/apt-slingshot/84312/
author: Florian Roth (Nextron Systems), Bartlomiej Czyz (@bczyz1)
date: 2019-03-04
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053.005
    - attack.s0111
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains:
            - '/delete'
            - '/change'
        CommandLine|contains|all:
            - '/TN'
            - '\Microsoft\Windows\Defrag\ScheduledDefrag'
    condition: selection
falsepositives:
    - Unknown
level: medium
