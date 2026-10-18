<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/system/service_control_manager/win_system_service_install_remcom.yml -->
title: RemCom Service Installation
id: 9e36ed87-4986-482e-8e3b-5c23ffff11bf
status: test
description: Detects RemCom service installation and execution events
references:
    - https://github.com/kavika13/RemCom/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-07
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection_eid:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_service:
        - ServiceName: 'RemComSvc'
        - ImagePath|endswith: '\RemComSvc.exe'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
