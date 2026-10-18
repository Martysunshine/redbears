<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/system/service_control_manager/win_system_service_install_tacticalrmm.yml -->
title: TacticalRMM Service Installation
id: 4bb79b62-ef12-4861-981d-2aab43fab642
status: test
description: Detects a TacticalRMM service installation. Tactical RMM is a remote monitoring & management tool.
references:
    - https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-11-28
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    product: windows
    service: system
detection:
    selection_root:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_service:
        - ImagePath|contains: 'tacticalrmm.exe'
        - ServiceName|contains: 'TacticalRMM Agent Service'
    condition: all of selection_*
falsepositives:
    - Legitimate use of the tool
level: medium
