<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_clip.yml -->
title: Invoke-Obfuscation Via Use Clip - Powershell
id: db92dd33-a3ad-49cf-8c2c-608c3e30ace0
status: test
description: Detects Obfuscated Powershell via use Clip.exe in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task29)
author: Nikita Nazarov, oscd.community
date: 2020-10-09
modified: 2024-04-15
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
        ScriptBlockText|re: '(?i)echo.*clip.*&&.*(Clipboard|i`?n`?v`?o`?k`?e`?)'
    condition: selection_4104
falsepositives:
    - Unknown
level: high
