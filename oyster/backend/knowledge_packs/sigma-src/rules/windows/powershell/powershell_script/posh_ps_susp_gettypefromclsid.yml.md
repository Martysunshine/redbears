<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_susp_gettypefromclsid.yml -->
title: Suspicious GetTypeFromCLSID ShellExecute
id: 8bc063d5-3a3a-4f01-a140-bc15e55e8437
status: test
description: Detects suspicious Powershell code that execute COM Objects
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.015/T1546.015.md#atomic-test-2---powershell-execute-com-object
author: frack113
date: 2022-04-02
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1546.015
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - '::GetTypeFromCLSID('
            - '.ShellExecute('
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: medium
