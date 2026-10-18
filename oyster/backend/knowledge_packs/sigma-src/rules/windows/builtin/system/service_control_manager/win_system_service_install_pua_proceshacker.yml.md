<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/system/service_control_manager/win_system_service_install_pua_proceshacker.yml -->
title: ProcessHacker Privilege Elevation
id: c4ff1eac-84ad-44dd-a6fb-d56a92fc43a9
status: test
description: Detects a ProcessHacker tool that elevated privileges to a very high level
references:
    - https://twitter.com/1kwpeter/status/1397816101455765504
author: Florian Roth (Nextron Systems)
date: 2021-05-27
modified: 2022-12-25
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1543.003
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ServiceName|startswith: 'ProcessHacker'
        AccountName: 'LocalSystem'
    condition: selection
falsepositives:
    - Unlikely
level: high
