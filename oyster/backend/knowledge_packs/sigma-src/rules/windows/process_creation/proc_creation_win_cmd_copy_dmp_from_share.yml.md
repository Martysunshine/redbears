<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_cmd_copy_dmp_from_share.yml -->
title: Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE
id: 044ba588-dff4-4918-9808-3f95e8160606
status: test
description: Detects usage of the copy builtin cmd command to copy files with the ".dmp"/".dump" extension from a remote share
references:
    - https://thedfirreport.com/2022/09/26/bumblebee-round-two/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-27
modified: 2023-09-12
tags:
    - attack.credential-access
logsource:
    category: process_creation
    product: windows
detection:
    # Example: copy \\<host>\\<folder>\\process.dmp C:\Users\process.dmp
    selection_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'Cmd.Exe'
    selection_cli:
        CommandLine|contains|all:
            - 'copy '
            - ' \\\\'
        CommandLine|contains:
            - '.dmp'
            - '.dump'
            - '.hdmp'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
