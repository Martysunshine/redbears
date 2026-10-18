<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2014/TA/Turla/proc_creation_win_apt_turla_commands_critical.yml -->
title: Turla Group Lateral Movement
id: c601f20d-570a-4cde-a7d6-e17f99cb8e7f
status: test
description: Detects automated lateral movement by Turla group
references:
    - https://securelist.com/the-epic-turla-operation/65545/
author: Markus Neis
date: 2017-11-07
modified: 2022-10-09
tags:
    - attack.g0010
    - attack.execution
    - attack.t1059
    - attack.lateral-movement
    - attack.t1021.002
    - attack.discovery
    - attack.t1083
    - attack.t1135
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - 'net use \\\\%DomainController%\C$ "P@ssw0rd" *'
            - 'dir c:\\*.doc* /s'
            - 'dir %TEMP%\\*.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical
