<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_lolbin_launch_vsdevshell.yml -->
title: Launch-VsDevShell.PS1 Proxy Execution
id: 45d3a03d-f441-458c-8883-df101a3bb146
status: test
description: Detects the use of the 'Launch-VsDevShell.ps1' Microsoft signed script to execute commands.
references:
    - https://twitter.com/nas_bench/status/1535981653239255040
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-19
tags:
    - attack.stealth
    - attack.t1216.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_script:
        CommandLine|contains: 'Launch-VsDevShell.ps1'
    selection_flags:
        CommandLine|contains:
            - 'VsWherePath '
            - 'VsInstallationPath '
    condition: all of selection_*
falsepositives:
    - Legitimate usage of the script by a developer
level: medium
