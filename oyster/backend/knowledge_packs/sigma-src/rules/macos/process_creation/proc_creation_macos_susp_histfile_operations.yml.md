<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_susp_histfile_operations.yml -->
title: Suspicious History File Operations
id: 508a9374-ad52-4789-b568-fc358def2c65
status: test
description: Detects commandline operations on shell history files
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md
author: 'Mikhail Larin, oscd.community'
date: 2020-10-17
modified: 2021-11-27
tags:
    - attack.credential-access
    - attack.t1552.003
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '.bash_history'
            - '.zsh_history'
            - '.zhistory'
            - '.history'
            - '.sh_history'
            - 'fish_history'
    condition: selection
falsepositives:
    - Legitimate administrative activity
    - Legitimate software, cleaning hist file
level: medium
