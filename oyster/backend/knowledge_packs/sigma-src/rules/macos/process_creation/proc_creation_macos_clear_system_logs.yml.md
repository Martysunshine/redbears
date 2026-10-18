<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_clear_system_logs.yml -->
title: Indicator Removal on Host - Clear Mac System Logs
id: acf61bd8-d814-4272-81f0-a7a269aa69aa
status: test
description: Detects deletion of local audit logs
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.002/T1070.002.md
author: remotephone, oscd.community
date: 2020-10-11
modified: 2022-09-16
tags:
    - attack.defense-impairment
    - attack.t1685.006
logsource:
    product: macos
    category: process_creation
detection:
    selection1:
        Image|endswith:
            - '/rm'
            - '/unlink'
            - '/shred'
    selection_cli_1:
        CommandLine|contains: '/var/log'
    selection_cli_2:
        CommandLine|contains|all:
            - '/Users/'
            - '/Library/Logs/'
    condition: selection1 and 1 of selection_cli*
falsepositives:
    - Legitimate administration activities
level: medium
