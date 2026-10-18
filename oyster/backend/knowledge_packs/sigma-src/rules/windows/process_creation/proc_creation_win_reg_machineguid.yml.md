<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_reg_machineguid.yml -->
title: Suspicious Query of MachineGUID
id: f5240972-3938-4e56-8e4b-e33893176c1f
status: test
description: Use of reg to get MachineGuid information
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-8---windows-machineguid-discovery
author: frack113
date: 2022-01-01
tags:
    - attack.discovery
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'
        CommandLine|contains|all:
            - 'SOFTWARE\Microsoft\Cryptography'
            - '/v '
            - 'MachineGuid'
    condition: selection
falsepositives:
    - Unknown
level: low
