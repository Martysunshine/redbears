<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_sysinternals_psexec_remote_execution.yml -->
title: Potential PsExec Remote Execution
id: ea011323-7045-460b-b2d7-0f7442ea6b38
status: test
description: Detects potential psexec command that initiate execution on a remote systems via common commandline flags used by the utility
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
    - https://www.poweradmin.com/paexec/
    - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-28
modified: 2025-09-01
tags:
    - attack.resource-development
    - attack.t1587.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Accepting EULA in commandline - often used in automated attacks
        CommandLine|contains|all:
            - 'accepteula'
            - ' -u '
            - ' -p '
            - ' \\\\'
    filter_main_localhost:
        CommandLine|contains:
            - '\\\\localhost'
            - '\\\\127.'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
