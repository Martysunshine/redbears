<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_msbuild_susp_parent_process.yml -->
title: Suspicious Msbuild Execution By Uncommon Parent Process
id: 33be4333-2c6b-44f4-ae28-102cdbde0a31
status: test
description: Detects suspicious execution of 'Msbuild.exe' by a uncommon parent process
references:
    - https://app.any.run/tasks/abdf586e-df0c-4d39-89a7-06bf24913401/
    - https://www.echotrail.io/insights/search/msbuild.exe
author: frack113
date: 2022-11-17
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\MSBuild.exe'
        - OriginalFileName: 'MSBuild.exe'
    filter_parent:
        ParentImage|endswith:
            - '\devenv.exe'
            - '\cmd.exe'
            - '\msbuild.exe'
            - '\python.exe'
            - '\explorer.exe'
            - '\nuget.exe'
    condition: selection and not filter_parent
falsepositives:
    - Unknown
level: medium
