<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_delete/file_delete_win_delete_powershell_command_history.yml -->
title: PowerShell Console History Logs Deleted
id: ff301988-c231-4bd0-834c-ac9d73b86586
status: test
description: Detects the deletion of the PowerShell console History logs which may indicate an attempt to destroy forensic evidence
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-15
tags:
    - attack.stealth
    - attack.t1070
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\PSReadLine\ConsoleHost_history.txt'
    condition: selection
falsepositives:
    - Unknown
level: medium
