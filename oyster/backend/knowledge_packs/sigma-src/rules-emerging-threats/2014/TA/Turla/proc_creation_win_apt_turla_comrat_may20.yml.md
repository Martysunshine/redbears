<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2014/TA/Turla/proc_creation_win_apt_turla_comrat_may20.yml -->
title: Turla Group Commands May 2020
id: 9e2e51c5-c699-4794-ba5a-29f5da40ac0c
status: test
description: Detects commands used by Turla group as reported by ESET in May 2020
references:
    - https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf
author: Florian Roth (Nextron Systems)
date: 2020-05-26
modified: 2025-10-19
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.stealth
    - attack.g0010
    - attack.execution
    - attack.t1059.001
    - attack.t1053.005
    - attack.t1027
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_cli_1:
        CommandLine|contains:
            - 'tracert -h 10 yahoo.com'
            - '.WSqmCons))|iex;'
            - 'Fr`omBa`se6`4Str`ing'
    selection_cli_2:
        CommandLine|re: 'net\s+use\s+https://docs.live.net'
        CommandLine|contains: '@aol.co.uk'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: critical
