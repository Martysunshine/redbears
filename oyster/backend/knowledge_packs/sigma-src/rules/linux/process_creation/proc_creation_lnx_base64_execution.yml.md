<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_base64_execution.yml -->
title: Linux Base64 Encoded Pipe to Shell
id: ba592c6d-6888-43c3-b8c6-689b8fe47337
status: test
description: Detects suspicious process command line that uses base64 encoded input for execution with a shell
references:
    - https://github.com/arget13/DDexec
    - https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally
author: pH-T (Nextron Systems)
date: 2022-07-26
modified: 2023-06-16
tags:
    - attack.stealth
    - attack.t1140
logsource:
    product: linux
    category: process_creation
detection:
    selection_base64:
        CommandLine|contains: 'base64 '
    selection_exec:
        - CommandLine|contains:
              - '| bash '
              - '| sh '
              - '|bash '
              - '|sh '
        - CommandLine|endswith:
              - ' |sh'
              - '| bash'
              - '| sh'
              - '|bash'
    condition: all of selection_*
falsepositives:
    - Legitimate administration activities
level: medium
