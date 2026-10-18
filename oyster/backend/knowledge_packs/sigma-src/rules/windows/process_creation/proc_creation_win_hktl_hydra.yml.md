<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_hydra.yml -->
title: HackTool - Hydra Password Bruteforce Execution
id: aaafa146-074c-11eb-adc1-0242ac120002
status: test
description: Detects command line parameters used by Hydra password guessing hack tool
references:
    - https://github.com/vanhauser-thc/thc-hydra
author: Vasiliy Burov
date: 2020-10-05
modified: 2023-02-04
tags:
    - attack.credential-access
    - attack.t1110
    - attack.t1110.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '-u '
            - '-p '
        CommandLine|contains:
            - '^USER^'
            - '^PASS^'
    condition: selection
falsepositives:
    - Software that uses the caret encased keywords PASS and USER in its command line
level: high
