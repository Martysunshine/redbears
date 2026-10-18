<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_susp_powershell_profile.yml -->
title: PowerShell Profile Modification
id: b5b78988-486d-4a80-b991-930eff3ff8bf
status: test
description: Detects the creation or modification of a powershell profile which could indicate suspicious activity as the profile can be used as a mean of persistence
references:
    - https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/
    - https://persistence-info.github.io/Data/powershellprofile.html
author: HieuTT35, Nasreddine Bencherchali (Nextron Systems)
date: 2019-10-24
modified: 2023-10-23
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1546.013
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '\Microsoft.PowerShell_profile.ps1'
            - '\PowerShell\profile.ps1'
            - '\Program Files\PowerShell\7-preview\profile.ps1'
            - '\Program Files\PowerShell\7\profile.ps1'
            - '\Windows\System32\WindowsPowerShell\v1.0\profile.ps1'
            - '\WindowsPowerShell\profile.ps1'
    condition: selection
falsepositives:
    - System administrator creating Powershell profile manually
level: medium
