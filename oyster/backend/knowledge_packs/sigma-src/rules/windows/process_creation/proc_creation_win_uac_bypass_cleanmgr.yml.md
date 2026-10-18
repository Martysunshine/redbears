<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_uac_bypass_cleanmgr.yml -->
title: UAC Bypass Using Disk Cleanup
id: b697e69c-746f-4a86-9f59-7bfff8eab881
status: test
description: Detects the pattern of UAC Bypass using scheduled tasks and variable expansion of cleanmgr.exe (UACMe 34)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021-08-30
modified: 2024-12-01
tags:
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|endswith: '"\system32\cleanmgr.exe /autoclean /d C:'
        ParentCommandLine: 'C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule'
        IntegrityLevel:
            - 'High'
            - 'System'
            - 'S-1-16-16384' # System
            - 'S-1-16-12288' # High
    condition: selection
falsepositives:
    - Unknown
level: high
