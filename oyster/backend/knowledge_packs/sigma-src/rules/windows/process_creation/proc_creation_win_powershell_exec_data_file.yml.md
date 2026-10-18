<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_powershell_exec_data_file.yml -->
title: Powershell Inline Execution From A File
id: ee218c12-627a-4d27-9e30-d6fb2fe22ed2
status: test
description: Detects inline execution of PowerShell code from a file
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=50
author: frack113
date: 2022-12-25
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_exec:
        CommandLine|contains:
            - 'iex '
            - 'Invoke-Expression '
            - 'Invoke-Command '
            - 'icm '
    selection_read:
        CommandLine|contains:
            - 'cat '
            - 'get-content '
            - 'type '
    selection_raw:
        CommandLine|contains: ' -raw'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
