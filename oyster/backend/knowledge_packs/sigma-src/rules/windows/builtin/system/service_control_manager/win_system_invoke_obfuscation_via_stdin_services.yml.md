<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_stdin_services.yml -->
title: Invoke-Obfuscation Via Stdin - System
id: 487c7524-f892-4054-b263-8a0ace63fc25
status: test
description: Detects Obfuscated Powershell via Stdin in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task28)
author: Nikita Nazarov, oscd.community
date: 2020-10-12
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
        # ImagePath|re: '(?i)(set).*&&\s?set.*(environment|invoke|\${?input).*&&.*"'
        ImagePath|contains|all:
            - 'set'
            - '&&'
        ImagePath|contains:
            - 'environment'
            - 'invoke'
            - 'input'
    condition: selection
falsepositives:
    - Unknown
level: high
