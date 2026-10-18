<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_delete/file_delete_win_delete_exchange_powershell_logs.yml -->
title: Exchange PowerShell Cmdlet History Deleted
id: a55349d8-9588-4c5a-8e3b-1925fe2a4ffe
status: test
description: Detects the deletion of the Exchange PowerShell cmdlet History logs which may indicate an attempt to destroy forensic evidence
references:
    - https://m365internals.com/2022/10/07/hunting-in-on-premises-exchange-server-logs/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-26
modified: 2022-12-30
tags:
    - attack.stealth
    - attack.t1070
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|startswith: '\Logging\CmdletInfra\LocalPowerShell\Cmdlet\'
        TargetFilename|contains: '_Cmdlet_'
    condition: selection
falsepositives:
    - Possible FP during log rotation
level: high
