<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_module/posh_pm_remote_powershell_session.yml -->
title: Remote PowerShell Session (PS Module)
id: 96b9f619-aa91-478f-bacb-c3e50f8df575
status: test
description: Detects remote PowerShell sessions
references:
    - https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g, Tim Shelton
date: 2019-08-10
modified: 2023-01-20
tags:
    - attack.execution
    - attack.t1059.001
    - attack.lateral-movement
    - attack.t1021.006
logsource:
    product: windows
    category: ps_module
    definition: 0ad03ef1-f21b-4a79-8ce8-e6900c54b65b
detection:
    selection:
        ContextInfo|contains|all:
            - ' = ServerRemoteHost ' #  HostName: 'ServerRemoteHost'  french : Nom d’hôte =
            - 'wsmprovhost.exe'      #  HostApplication|contains: 'wsmprovhost.exe' french  Application hôte =
    filter_pwsh_archive:
        ContextInfo|contains: '\Windows\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Archive\Microsoft.PowerShell.Archive.psm1'
    condition: selection and not 1 of filter_*
falsepositives:
    - Legitimate use remote PowerShell sessions
level: high
