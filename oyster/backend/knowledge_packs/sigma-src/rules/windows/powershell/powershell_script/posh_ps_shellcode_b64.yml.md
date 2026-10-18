<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_shellcode_b64.yml -->
title: PowerShell ShellCode
id: 16b37b70-6fcf-4814-a092-c36bd3aafcbd
status: test
description: Detects Base64 encoded Shellcode
references:
    - https://twitter.com/cyb3rops/status/1063072865992523776
author: David Ledbetter (shellcode), Florian Roth (Nextron Systems)
date: 2018-11-17
modified: 2024-01-25
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains:
            - 'OiCAAAAYInlM'
            - 'OiJAAAAYInlM'
    condition: selection
falsepositives:
    - Unknown
level: high
