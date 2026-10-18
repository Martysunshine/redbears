<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2019/TA/EquationGroup/proc_creation_win_apt_equationgroup_dll_u_load.yml -->
title: Equation Group DLL_U Export Function Load
id: d465d1d8-27a2-4cca-9621-a800f37cf72e
status: stable
description: Detects a specific export function name used by one of EquationGroup tools
references:
    - https://github.com/00derp/EquationGroupLeak/search?utf8=%E2%9C%93&q=dll_u&type=
    - https://twitter.com/cyb3rops/status/972186477512839170
author: Florian Roth (Nextron Systems)
date: 2019-03-04
modified: 2023-03-09
tags:
    - attack.stealth
    - attack.g0020
    - attack.t1218.011
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains: '-export dll_u'
        - CommandLine|endswith:
              - ',dll_u'
              - ' dll_u'
    condition: selection
falsepositives:
    - Unlikely
level: critical
