<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml -->
title: Linux Shell Pipe to Shell
id: 880973f3-9708-491c-a77b-2a35a1921158
status: test
description: Detects suspicious process command line that starts with a shell that executes something and finally gets piped into another shell
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2022-03-14
modified: 2022-07-26
tags:
    - attack.stealth
    - attack.t1140
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|startswith:
            - 'sh -c '
            - 'bash -c '
    selection_exec:
        - CommandLine|contains:
              - '| bash '
              - '| sh '
              - '|bash '
              - '|sh '
        - CommandLine|endswith:
              - '| bash'
              - '| sh'
              - '|bash'
              - ' |sh'
    condition: all of selection*
falsepositives:
    - Legitimate software that uses these patterns
level: medium
