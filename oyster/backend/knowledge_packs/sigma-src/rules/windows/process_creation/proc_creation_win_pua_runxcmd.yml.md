<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_pua_runxcmd.yml -->
title: PUA - RunXCmd Execution
id: 93199800-b52a-4dec-b762-75212c196542
status: test
description: Detects the use of the RunXCmd tool to execute commands with System or TrustedInstaller accounts
references:
    - https://www.d7xtech.com/free-software/runx/
    - https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
author: Florian Roth (Nextron Systems)
date: 2022-01-24
modified: 2023-02-14
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    category: process_creation
    product: windows
detection:
    selection_account:
        CommandLine|contains:
            - ' /account=system '
            - ' /account=ti '
    selection_exec:
        CommandLine|contains: '/exec='
    condition: all of selection_*
falsepositives:
    - Legitimate use by administrators
level: high
