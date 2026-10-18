<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_var.yml -->
title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell
id: e54f5149-6ba3-49cf-b153-070d24679126
status: test
description: Detects Obfuscated Powershell via VAR++ LAUNCHER
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task27)
author: Timur Zinniatullin, oscd.community
date: 2020-10-13
modified: 2024-04-05
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
        ScriptBlockText|re: '(?i)&&set.*(\{\d\}){2,}\\"\s+?-f.*&&.*cmd.*/c' # FPs with |\/r
    condition: selection_4104
falsepositives:
    - Unknown
level: high
