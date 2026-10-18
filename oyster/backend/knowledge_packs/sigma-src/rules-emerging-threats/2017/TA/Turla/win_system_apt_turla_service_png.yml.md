<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2017/TA/Turla/win_system_apt_turla_service_png.yml -->
title: Turla PNG Dropper Service
id: 1228f8e2-7e79-4dea-b0ad-c91f1d5016c1
status: test
description: This method detects malicious services mentioned in Turla PNG dropper report by NCC Group in November 2018
references:
    - https://research.nccgroup.com/2018/11/22/turla-png-dropper-is-back/
author: Florian Roth (Nextron Systems)
date: 2018-11-23
modified: 2021-11-30
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.g0010
    - attack.t1543.003
    - detection.emerging-threats
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ServiceName: 'WerFaultSvc'
    condition: selection
falsepositives:
    - Unlikely
level: critical
