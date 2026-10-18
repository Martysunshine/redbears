<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_dxcap_arbitrary_binary_execution.yml -->
title: New Capture Session Launched Via DXCap.EXE
id: 60f16a96-db70-42eb-8f76-16763e333590
status: test
description: |
    Detects the execution of "DXCap.EXE" with the "-c" flag, which allows a user to launch any arbitrary binary or windows package through DXCap itself. This can be abused to potentially bypass application whitelisting.
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Dxcap/
    - https://twitter.com/harr0ey/status/992008180904419328
author: Beyu Denis, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2019-10-26
modified: 2022-06-09
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\DXCap.exe'
        - OriginalFileName: 'DXCap.exe'
    selection_cli:
        CommandLine|contains: ' -c ' # The ".exe" is not required to run the binary
    condition: all of selection*
falsepositives:
    - Legitimate execution of dxcap.exe by legitimate user
level: medium
