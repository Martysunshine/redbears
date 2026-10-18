<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2017/TA/Turla/win_system_apt_carbonpaper_turla.yml -->
title: Turla Service Install
id: 1df8b3da-b0ac-4d8a-b7c7-6cb7c24160e4
status: test
description: This method detects a service install of malicious services mentioned in Carbon Paper - Turla report by ESET
references:
    - https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
author: Florian Roth (Nextron Systems)
date: 2017-03-31
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
        ServiceName:
            - 'srservice'
            - 'ipvpn'
            - 'hkmsvc'
    condition: selection
falsepositives:
    - Unknown
level: high
