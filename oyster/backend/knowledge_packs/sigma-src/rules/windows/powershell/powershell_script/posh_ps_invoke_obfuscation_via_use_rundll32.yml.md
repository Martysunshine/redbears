<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_rundll32.yml -->
title: Invoke-Obfuscation Via Use Rundll32 - PowerShell
id: a5a30a6e-75ca-4233-8b8c-42e0f2037d3b
status: test
description: Detects Obfuscated Powershell via use Rundll32 in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009
author: Nikita Nazarov, oscd.community
date: 2019-10-08
modified: 2022-11-29
tags:
    - attack.stealth
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_4104:
        ScriptBlockText|contains|all:
            - '&&'
            - 'rundll32'
            - 'shell32.dll'
            - 'shellexec_rundll'
        ScriptBlockText|contains:
            - 'value'
            - 'invoke'
            - 'comspec'
            - 'iex'
    condition: selection_4104
falsepositives:
    - Unknown
level: high
