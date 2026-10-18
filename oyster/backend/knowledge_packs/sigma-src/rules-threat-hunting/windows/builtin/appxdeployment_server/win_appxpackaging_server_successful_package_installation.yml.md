<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/builtin/appxdeployment_server/win_appxpackaging_server_successful_package_installation.yml -->
title: Successful MSIX/AppX Package Installation
id: 289dfa9e-e378-4a56-a9d4-7ed5ee218029
status: experimental
description: |
    Detects successful MSIX/AppX package installations on Windows systems by monitoring EventID 854 in the Microsoft-Windows-AppXDeployment-Server/Operational log.
    While most installations are legitimate, this can help identify unauthorized or suspicious package installations.
    It is crucial to monitor such events as threat actors may exploit MSIX/AppX packages to deliver and execute malicious payloads.
references:
    - https://www.splunk.com/en_us/blog/security/msix-weaponization-threat-detection-splunk.html
author: Michael Haag, Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-11-03
tags:
    - attack.execution
    - attack.t1204.002
    - detection.threat-hunting
logsource:
    product: windows
    service: appxdeployment-server
detection:
    selection:
        EventID: 854
    condition: selection
falsepositives:
    - Legitimate MSIX/AppX package installations
level: low
