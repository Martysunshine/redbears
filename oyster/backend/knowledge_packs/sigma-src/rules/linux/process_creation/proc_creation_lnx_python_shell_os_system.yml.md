<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_python_shell_os_system.yml -->
title: Inline Python Execution - Spawn Shell Via OS System Library
id: 2d2f44ff-4611-4778-a8fc-323a0e9850cc
status: test
description: |
    Detects execution of inline Python code via the "-c" in order to call the "system" function from the "os" library, and spawn a shell.
references:
    - https://gtfobins.github.io/gtfobins/python/#shell
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: 2024-09-02
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        - Image|endswith:
              - '/python'
              - '/python2'
              - '/python3'
        - Image|contains:
              - '/python2.'  # python image is always of the form ../python3.10; ../python is just a symlink
              - '/python3.'
    selection_cli:
        CommandLine|contains|all:
            - ' -c '
            - 'os.system('
        CommandLine|contains:
            - '/bin/bash'
            - '/bin/dash'
            - '/bin/fish'
            - '/bin/sh'
            - '/bin/zsh'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
