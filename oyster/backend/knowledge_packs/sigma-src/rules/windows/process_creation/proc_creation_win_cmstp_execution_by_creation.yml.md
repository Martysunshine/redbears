<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_cmstp_execution_by_creation.yml -->
title: CMSTP Execution Process Creation
id: 7d4cdc5a-0076-40ca-aac8-f7e714570e47
status: stable
description: Detects various indicators of Microsoft Connection Manager Profile Installer execution
references:
    - https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
author: Nik Seetharaman
date: 2018-07-16
modified: 2020-12-23
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218.003
    - attack.g0069
    - car.2019-04-001
logsource:
    category: process_creation
    product: windows
detection:
    # CMSTP Spawning Child Process
    selection:
        ParentImage|endswith: '\cmstp.exe'
    condition: selection
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high
