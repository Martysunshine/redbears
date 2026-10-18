<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_evil_winrm.yml -->
title: HackTool - WinRM Access Via Evil-WinRM
id: a197e378-d31b-41c0-9635-cfdf1c1bb423
status: test
description: Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.006/T1021.006.md#atomic-test-3---winrm-access-with-evil-winrm
    - https://github.com/Hackplayers/evil-winrm
author: frack113
date: 2022-01-07
modified: 2023-02-13
tags:
    - attack.lateral-movement
    - attack.t1021.006
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ruby.exe'
        CommandLine|contains|all:
            - '-i '
            - '-u '
            - '-p '
    condition: selection
falsepositives:
    - Unknown
level: medium
