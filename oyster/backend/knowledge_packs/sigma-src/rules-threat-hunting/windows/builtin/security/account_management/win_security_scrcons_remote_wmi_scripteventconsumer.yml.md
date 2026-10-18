<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/builtin/security/account_management/win_security_scrcons_remote_wmi_scripteventconsumer.yml -->
title: Potential Remote WMI ActiveScriptEventConsumers Activity
id: 9599c180-e3a8-4743-8f92-7fb96d3be648
status: test
description: |
    Detect potential adversaries leveraging WMI ActiveScriptEventConsumers remotely to move laterally in a network.
    This event is best correlated and used as an enrichment to determine the potential lateral movement activity.
references:
    - https://threathunterplaybook.com/hunts/windows/200902-RemoteWMIActiveScriptEventConsumers/notebook.html
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-09-02
modified: 2024-09-02
tags:
    - attack.lateral-movement
    - attack.privilege-escalation
    - detection.threat-hunting
    - attack.persistence
    - attack.t1546.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        ProcessName|endswith: 'scrcons.exe'
    filter_main_local_system:
        TargetLogonId: '0x3e7' # Local System
    condition: selection and not 1 of filter_main_*
falsepositives:
    - SCCM
level: medium
