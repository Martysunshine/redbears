<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_wpbbin_potential_persistence.yml -->
title: UEFI Persistence Via Wpbbin - ProcessCreation
id: 4abc0ec4-db5a-412f-9632-26659cddf145
status: test
description: Detects execution of the binary "wpbbin" which is used as part of the UEFI based persistence method described in the reference section
references:
    - https://grzegorztworek.medium.com/using-uefi-to-inject-executable-files-into-bitlocker-protected-drives-8ff4ca59c94c
    - https://persistence-info.github.io/Data/wpbbin.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-18
tags:
    - attack.persistence
    - attack.stealth
    - attack.t1542.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image: 'C:\Windows\System32\wpbbin.exe'
    condition: selection
falsepositives:
    - Legitimate usage of the file by hardware manufacturer such as lenovo (Thanks @0gtweet for the tip)
level: high
