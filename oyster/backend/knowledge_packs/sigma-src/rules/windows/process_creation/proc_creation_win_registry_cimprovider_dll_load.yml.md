<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_registry_cimprovider_dll_load.yml -->
title: DLL Execution Via Register-cimprovider.exe
id: a2910908-e86f-4687-aeba-76a5f996e652
status: test
description: Detects using register-cimprovider.exe to execute arbitrary dll file.
references:
    - https://twitter.com/PhilipTsukerman/status/992021361106268161
    - https://lolbas-project.github.io/lolbas/Binaries/Register-cimprovider/
author: Ivan Dyachkov, Yulia Fomina, oscd.community
date: 2020-10-07
modified: 2021-11-27
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.t1574
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\register-cimprovider.exe'
        CommandLine|contains|all:
            - '-path'
            - 'dll'
    condition: selection
falsepositives:
    - Unknown
level: medium
