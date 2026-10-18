<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml -->
title: Potential Perl Reverse Shell Execution
id: 259df6bc-003f-4306-9f54-4ff1a08fa38e
status: test
description: Detects execution of the perl binary with the "-e" flag and common strings related to potential reverse shell activity
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
author: '@d4ns4n_, Nasreddine Bencherchali (Nextron Systems)'
date: 2023-04-07
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/perl'
        CommandLine|contains: ' -e '
    selection_content:
        - CommandLine|contains|all:
              - 'fdopen('
              - '::Socket::INET'
        - CommandLine|contains|all:
              - 'Socket'
              - 'connect'
              - 'open'
              - 'exec'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
