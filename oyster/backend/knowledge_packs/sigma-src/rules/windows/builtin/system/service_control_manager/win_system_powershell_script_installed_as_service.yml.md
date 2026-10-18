<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/system/service_control_manager/win_system_powershell_script_installed_as_service.yml -->
title: PowerShell Scripts Installed as Services
id: a2e5019d-a658-4c6a-92bf-7197b54e2cae
status: test
description: Detects powershell script installed as a Service
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
author: oscd.community, Natalia Shornikova
date: 2020-10-06
modified: 2022-12-25
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains:
            - 'powershell'
            - 'pwsh'
    condition: selection
falsepositives:
    - Unknown
level: high
