<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_reg_volsnap_disable.yml -->
title: Disabled Volume Snapshots
id: dee4af55-1f22-4e1d-a9d2-4bdc7ecb472a
status: test
description: Detects commands that temporarily turn off Volume Snapshots
references:
    - https://twitter.com/0gtweet/status/1354766164166115331
author: Florian Roth (Nextron Systems)
date: 2021-01-28
modified: 2023-12-15
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\Services\VSS\Diag'
            - '/d Disabled'
    condition: selection
falsepositives:
    - Legitimate administration
level: high
