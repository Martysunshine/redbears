<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/process_creation/proc_creation_win_powershell_abnormal_commandline_size.yml -->
title: Unusually Long PowerShell CommandLine
id: d0d28567-4b9a-45e2-8bbc-fb1b66a1f7f6
status: test
description: Detects unusually long PowerShell command lines with a length of 1000 characters or more
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
author: oscd.community, Natalia Shornikova
date: 2020-10-06
modified: 2023-04-14
tags:
    - attack.execution
    - attack.t1059.001
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection_powershell:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
        - Description: 'Windows Powershell'
        - Product: 'PowerShell Core 6'
    selection_length:
        CommandLine|re: '.{1000,}'
    condition: all of selection_*
falsepositives:
    - Unknown
level: low
