<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_remcom_service.yml -->
title: RemCom Service File Creation
id: 7eff1a7f-dd45-4c20-877a-f21e342a7611
status: test
description: Detects default RemCom service filename which indicates RemCom service installation and execution
references:
    - https://github.com/kavika13/RemCom/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-04
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\RemComSvc.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
