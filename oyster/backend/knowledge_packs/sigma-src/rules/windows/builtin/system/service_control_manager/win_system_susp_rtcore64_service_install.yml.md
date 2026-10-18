<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/system/service_control_manager/win_system_susp_rtcore64_service_install.yml -->
title: RTCore Suspicious Service Installation
id: 91c49341-e2ef-40c0-ac45-49ec5c3fe26c
status: test
description: Detects the installation of RTCore service. Which could be an indication of Micro-Star MSI Afterburner vulnerable driver abuse
references:
    - https://github.com/br-sn/CheekyBlinder/blob/e1764a8a0e7cda8a3716aefa35799f560686e01c/CheekyBlinder/CheekyBlinder.cpp
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-30
tags:
    - attack.persistence
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ServiceName: 'RTCore64'
    condition: selection
falsepositives:
    - Unknown
level: high
