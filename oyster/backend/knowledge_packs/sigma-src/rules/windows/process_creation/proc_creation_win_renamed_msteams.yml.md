<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_renamed_msteams.yml -->
title: Renamed Microsoft Teams Execution
id: 88f46b67-14d4-4f45-ac2c-d66984f22191
status: test
description: Detects the execution of a renamed Microsoft Teams binary.
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-07-12
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName:
            - 'msteams.exe'
            - 'teams.exe'
    filter_main_legit_names:
        Image|endswith:
            - '\msteams.exe'
            - '\teams.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
