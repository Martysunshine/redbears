<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_susp_interactive_bash.yml -->
title: Interactive Bash Suspicious Children
id: ea3ecad2-db86-4a89-ad0b-132a10d2db55
status: test
description: Detects suspicious interactive bash as a parent to rather uncommon child processes
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2022-03-14
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.004
    - attack.t1036
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        ParentCommandLine: 'bash -i'
    anomaly1:
        CommandLine|contains:
            - '-c import '
            - 'base64'
            - 'pty.spawn'
    anomaly2:
        Image|endswith:
            - 'whoami'
            - 'iptables'
            - '/ncat'
            - '/nc'
            - '/netcat'
    condition: selection and 1 of anomaly*
falsepositives:
    - Legitimate software that uses these patterns
level: medium
