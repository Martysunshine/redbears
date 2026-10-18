<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_set/registry_set_powershell_as_service.yml -->
title: PowerShell as a Service in Registry
id: 4a5f5a5e-ac01-474b-9b4e-d61298c9df1d
status: test
description: Detects that a powershell code is written to the registry as a service.
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
author: oscd.community, Natalia Shornikova
date: 2020-10-06
modified: 2023-08-17
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Services\'
        TargetObject|endswith: '\ImagePath'
        Details|contains:
            - 'powershell'
            - 'pwsh'
    condition: selection
falsepositives:
    - Unknown
level: high
