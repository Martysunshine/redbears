<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_rsync_shell_execution.yml -->
title: Shell Execution via Rsync - Linux
id: e2326866-609f-4015-aea9-7ec634e8aa04
status: experimental
description: |
    Detects the use of the "rsync" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/rsync/#shell
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.), Florian Roth
date: 2024-09-02
modified: 2025-01-18
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/rsync'
            - '/rsyncd'
        CommandLine|contains: ' -e '
    selection_cli:
        CommandLine|contains:
            - '/ash '
            - '/bash '
            - '/dash '
            - '/csh '
            - '/sh '
            - '/zsh '
            - '/tcsh '
            - '/ksh '
            - "'ash "
            - "'bash "
            - "'dash "
            - "'csh "
            - "'sh "
            - "'zsh "
            - "'tcsh "
            - "'ksh "
    condition: all of selection_*
falsepositives:
    - Legitimate cases in which "rsync" is used to execute a shell
level: high
