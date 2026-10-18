<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_rundll32_services.yml -->
title: Invoke-Obfuscation Via Use Rundll32 - System
id: 641a4bfb-c017-44f7-800c-2aee0184ce9b
status: test
description: Detects Obfuscated Powershell via use Rundll32 in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task30)
author: Nikita Nazarov, oscd.community
date: 2020-10-09
modified: 2022-11-29
tags:
    - attack.stealth
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains|all:
            - '&&'
            - 'rundll32'
            - 'shell32.dll'
            - 'shellexec_rundll'
        ImagePath|contains:
            - 'value'
            - 'invoke'
            - 'comspec'
            - 'iex'
    condition: selection
falsepositives:
    - Unknown
level: high
