<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_vim_shell_execution.yml -->
title: Vim GTFOBin Abuse - Linux
id: 7ab8f73a-fcff-428b-84aa-6a5ff7877dea
status: test
description: |
    Detects the use of "vim" and it's siblings commands to execute a shell or proxy commands.
    Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/vi/
    - https://gtfobins.github.io/gtfobins/vim/
    - https://gtfobins.github.io/gtfobins/rvim/
    - https://gtfobins.github.io/gtfobins/vimdiff/
author: Nasreddine Bencherchali (Nextron Systems), Luc Génaux
date: 2022-12-28
modified: 2026-06-05
tags:
    - attack.execution
    - attack.discovery
    - attack.t1059
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/rvim'
            - '/vi'
            - '/vim'
            - '/vimdiff'
        CommandLine|contains:
            - ' --cmd '
            - ' -c'
    selection_cli:
        CommandLine|contains:
            - ':!/'
            - ':!$'
            - ':!..'
            - ':lua '
            - ':py '
            - ':shell'
            - '/bin/bash'
            - '/bin/dash'
            - '/bin/fish'
            - '/bin/sh'
            - '/bin/csh'
            - '/bin/ksh'
            - '/bin/zsh'
            - '/bin/tmux'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
