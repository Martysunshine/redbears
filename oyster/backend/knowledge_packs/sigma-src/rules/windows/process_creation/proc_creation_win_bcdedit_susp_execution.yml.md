<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_bcdedit_susp_execution.yml -->
title: Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE
id: c9fbe8e9-119d-40a6-9b59-dd58a5d84429
status: test
description: Detects potential malicious and unauthorized usage of bcdedit.exe
references:
    - https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set
    - https://twitter.com/malwrhunterteam/status/1372536434125512712/photo/2
author: '@neu5ron'
date: 2019-02-07
modified: 2023-02-15
tags:
    - attack.stealth
    - attack.t1070
    - attack.persistence
    - attack.t1542.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\bcdedit.exe'
        - OriginalFileName: 'bcdedit.exe'
    selection_cli:
        CommandLine|contains:
            - 'delete'
            - 'deletevalue'
            - 'import'
            - 'safeboot'
            - 'network'
    condition: all of selection_*
level: medium
