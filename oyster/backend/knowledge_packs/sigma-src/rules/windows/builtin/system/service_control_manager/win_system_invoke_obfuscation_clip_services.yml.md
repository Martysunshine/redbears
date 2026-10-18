<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_clip_services.yml -->
title: Invoke-Obfuscation CLIP+ Launcher - System
id: f7385ee2-0e0c-11eb-adc1-0242ac120002
status: test
description: Detects Obfuscated use of Clip.exe to execute PowerShell
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task 26)
author: Jonathan Cheong, oscd.community
date: 2020-10-13
modified: 2023-02-20
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
            - 'cmd'
            - '&&'
            - 'clipboard]::'
    condition: selection
falsepositives:
    - Unknown
level: high
