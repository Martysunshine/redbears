<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_mshta_services.yml -->
title: Invoke-Obfuscation Via Use MSHTA - System
id: 7e9c7999-0f9b-4d4a-a6ed-af6d553d4af4
status: test
description: Detects Obfuscated Powershell via use MSHTA in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task31)
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
            - 'mshta'
            - 'vbscript:createobject'
    condition: selection
falsepositives:
    - Unknown
level: high
