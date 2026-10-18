<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/bits_client/win_bits_client_new_job_via_powershell.yml -->
title: New BITS Job Created Via PowerShell
id: fe3a2d49-f255-4d10-935c-bda7391108eb
status: test
description: Detects the creation of a new bits job by PowerShell
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1197/T1197.md
author: frack113
date: 2022-03-01
modified: 2023-03-27
tags:
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.t1197
logsource:
    product: windows
    service: bits-client
detection:
    selection:
        EventID: 3
        processPath|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    condition: selection
falsepositives:
    - Administrator PowerShell scripts
level: low
