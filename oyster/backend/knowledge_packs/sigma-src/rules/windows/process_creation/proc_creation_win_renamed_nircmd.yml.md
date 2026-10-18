<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_renamed_nircmd.yml -->
title: Renamed NirCmd.EXE Execution
id: 264982dc-dbad-4dce-b707-1e0d3e0f73d9
status: test
description: Detects the execution of a renamed "NirCmd.exe" binary based on the PE metadata fields.
references:
    - https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/
    - https://www.nirsoft.net/utils/nircmd.html
author: X__Junior (Nextron Systems)
date: 2024-03-11
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'NirCmd.exe'
    filter_main_img:
        Image|endswith:
            - '\nircmd.exe'
            - '\nircmdc.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
