<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2023/TA/FIN7/file_event_win_apt_fin7_powershell_scripts_naming_convention.yml -->
title: Potential APT FIN7 Related PowerShell Script Created
id: a88d9f45-ec8a-4b0e-85ee-c9f6a65e9128
status: test
description: Detects PowerShell script file creation with specific name or suffix which was seen being used often by FIN7 PowerShell scripts
references:
    - https://labs.withsecure.com/publications/fin7-target-veeam-servers
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-04
tags:
    - attack.execution
    - attack.g0046
    - detection.emerging-threats
logsource:
    category: file_event
    product: windows
detection:
    selection:
        - TargetFilename|endswith: '_64refl.ps1'
        - TargetFilename: 'host_ip.ps1'
    condition: selection
falsepositives:
    - Unknown
level: high
