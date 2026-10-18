<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_susp_history_delete.yml -->
title: History File Deletion
id: 1182f3b3-e716-4efa-99ab-d2685d04360f
status: test
description: Detects events in which a history file gets deleted, e.g. the ~/bash_history to remove traces of malicious activity
references:
    - https://github.com/sleventyeleven/linuxprivchecker/
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md
author: Florian Roth (Nextron Systems)
date: 2022-06-20
modified: 2022-09-15
tags:
    - attack.impact
    - attack.t1565.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/rm'
            - '/unlink'
            - '/shred'
    selection_history:
        - CommandLine|contains:
              - '/.bash_history'
              - '/.zsh_history'
        - CommandLine|endswith:
              - '_history'
              - '.history'
              - 'zhistory'
    condition: all of selection*
falsepositives:
    - Legitimate administration activities
level: high
