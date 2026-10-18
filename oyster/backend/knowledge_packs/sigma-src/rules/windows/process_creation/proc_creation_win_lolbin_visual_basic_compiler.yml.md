<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_lolbin_visual_basic_compiler.yml -->
title: Visual Basic Command Line Compiler Usage
id: 7b10f171-7f04-47c7-9fa2-5be43c76e535
status: test
description: Detects successful code compilation via Visual Basic Command Line Compiler that utilizes Windows Resource to Object Converter.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Vbc/
author: 'Ensar Şamil, @sblmsrsn, @oscd_initiative'
date: 2020-10-07
modified: 2021-11-27
tags:
    - attack.stealth
    - attack.t1027.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\vbc.exe'
        Image|endswith: '\cvtres.exe'
    condition: selection
falsepositives:
    - Utilization of this tool should not be seen in enterprise environment
level: high
