<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_git_shell_execution.yml -->
title: Shell Execution via Git - Linux
id: 47b3bbd4-1bf7-48cc-84ab-995362aaa75a
status: test
description: |
    Detects the use of the "git" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/git/#shell
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: 2024-09-02
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith: '/git'
        ParentCommandLine|contains|all:
            - ' -p '
            - 'help'
        CommandLine|contains:
            - 'bash 0<&1'
            - 'dash 0<&1'
            - 'sh 0<&1'
    condition: selection
falsepositives:
    - Unknown
level: high
