<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/system/service_control_manager/win_system_service_install_paexec.yml -->
title: PAExec Service Installation
id: de7ce410-b3fb-4e8a-b38c-3b999e2c3420
status: test
description: Detects PAExec service installation
references:
    - https://www.poweradmin.com/paexec/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-26
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection_eid:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_image:
        - ServiceName|startswith: 'PAExec-'
        - ImagePath|startswith: 'C:\WINDOWS\PAExec-'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
