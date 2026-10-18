<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_sysinternals_livekd_default_dump_name.yml -->
title: LiveKD Kernel Memory Dump File Created
id: 814ddeca-3d31-4265-8e07-8cc54fb44903
status: test
description: Detects the creation of a file that has the same name as the default LiveKD kernel memory dump.
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-16
tags:
    - attack.privilege-escalation
    - attack.stealth
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename: 'C:\Windows\livekd.dmp'
    condition: selection
falsepositives:
    - In rare occasions administrators might leverage LiveKD to perform live kernel debugging. This should not be allowed on production systems. Investigate and apply additional filters where necessary.
level: high
