<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_device_credential_deployment.yml -->
title: DeviceCredentialDeployment Execution
id: b8b1b304-a60f-4999-9a6e-c547bde03ffd
status: test
description: |
    Detects the execution of DeviceCredentialDeployment to hide a process from view.
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/147
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-19
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\DeviceCredentialDeployment.exe'
    condition: selection
falsepositives:
    - Unlikely
level: medium
