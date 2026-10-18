<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/powershell/powershell_script/posh_ps_remove_item_path.yml -->
title: Use Of Remove-Item to Delete File - ScriptBlock
id: b8af5f36-1361-4ebe-9e76-e36128d947bf
status: test
description: PowerShell Remove-Item  with -Path to delete a file or a folder with "-Recurse"
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.004/T1070.004.md
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/Remove-Item?view=powershell-5.1&viewFallbackFrom=powershell-7
author: frack113
date: 2022-01-15
modified: 2022-03-17
tags:
    - attack.stealth
    - attack.t1070.004
    - detection.threat-hunting
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains:
            - 'Remove-Item -Path '
            - 'del -Path '
            - 'erase -Path '
            - 'rd -Path '
            - 'ri -Path '
            - 'rm -Path '
            - 'rmdir -Path '
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: low
