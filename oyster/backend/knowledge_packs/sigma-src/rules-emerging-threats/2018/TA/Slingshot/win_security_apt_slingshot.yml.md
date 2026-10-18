<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2018/TA/Slingshot/win_security_apt_slingshot.yml -->
title: Defrag Deactivation - Security
id: c5a178bf-9cfb-4340-b584-e4df39b6a3e7
related:
    - id: 958d81aa-8566-4cea-a565-59ccd4df27b0
      type: derived
status: test
description: Detects the deactivation and disabling of the Scheduled defragmentation task as seen by Slingshot APT group
references:
    - https://securelist.com/apt-slingshot/84312/
author: Florian Roth (Nextron Systems), Bartlomiej Czyz (@bczyz1)
date: 2019-03-04
modified: 2022-11-27
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053
    - attack.s0111
    - detection.emerging-threats
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Audit Other Object Access Events > Success'
detection:
    selection:
        EventID: 4701
        TaskName: '\Microsoft\Windows\Defrag\ScheduledDefrag'
    condition: selection
falsepositives:
    - Unknown
level: medium
