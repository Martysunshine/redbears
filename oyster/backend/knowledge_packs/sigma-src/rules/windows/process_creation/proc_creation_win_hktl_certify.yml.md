<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_certify.yml -->
title: HackTool - Certify Execution
id: 762f2482-ff21-4970-8939-0aa317a886bb
status: test
description: Detects Certify a tool for Active Directory certificate abuse based on PE metadata characteristics and common command line arguments.
references:
    - https://github.com/GhostPack/Certify
author: pH-T (Nextron Systems)
date: 2023-04-17
modified: 2023-04-25
tags:
    - attack.discovery
    - attack.credential-access
    - attack.t1649
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\Certify.exe'
        - OriginalFileName: 'Certify.exe'
        - Description|contains: 'Certify'
    selection_cli_commands:
        CommandLine|contains:
            - '.exe cas '
            - '.exe find '
            - '.exe pkiobjects '
            - '.exe request '
            - '.exe download '
    selection_cli_options:
        CommandLine|contains:
            - ' /vulnerable'
            - ' /template:'
            - ' /altname:'
            - ' /domain:'
            - ' /path:'
            - ' /ca:'
    condition: selection_img or all of selection_cli_*
falsepositives:
    - Unknown
level: high
