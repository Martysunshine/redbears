<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_delete/file_delete_win_delete_event_log_files.yml -->
title: EventLog EVTX File Deleted
id: 63c779ba-f638-40a0-a593-ddd45e8b1ddc
status: test
description: Detects the deletion of the event log files which may indicate an attempt to destroy forensic evidence
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
        TargetFilename|startswith: 'C:\Windows\System32\winevt\Logs\'
        TargetFilename|endswith: '.evtx'
    condition: selection
falsepositives:
    - Unknown
level: medium
