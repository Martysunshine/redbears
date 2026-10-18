<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_access/proc_access_win_hktl_cobaltstrike_bof_injection_pattern.yml -->
title: HackTool - CobaltStrike BOF Injection Pattern
id: 09706624-b7f6-455d-9d02-adee024cee1d
status: test
description: Detects a typical pattern of a CobaltStrike BOF which inject into other processes
references:
    - https://github.com/boku7/injectAmsiBypass
    - https://github.com/boku7/spawn
author: Christian Burkard (Nextron Systems)
date: 2021-08-04
modified: 2023-11-28
tags:
    - attack.execution
    - attack.defense-impairment
    - attack.t1106
    - attack.t1685
logsource:
    category: process_access
    product: windows
detection:
    selection:
        CallTrace|re: '^C:\\Windows\\SYSTEM32\\ntdll\.dll\+[a-z0-9]{4,6}\|C:\\Windows\\System32\\KERNELBASE\.dll\+[a-z0-9]{4,6}\|UNKNOWN\([A-Z0-9]{16}\)$'
        GrantedAccess:
            - '0x1028'
            - '0x1fffff'
    condition: selection
falsepositives:
    - Unknown
level: high
