<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_wmi_persistence_script_event_consumer_write.yml -->
title: WMI Persistence - Script Event Consumer File Write
id: 33f41cdd-35ac-4ba8-814b-c6a4244a1ad4
status: test
description: Detects file writes of WMI script event consumer
references:
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
author: Thomas Patzke
date: 2018-03-07
modified: 2021-11-27
tags:
    - attack.privilege-escalation
    - attack.t1546.003
    - attack.persistence
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image: 'C:\WINDOWS\system32\wbem\scrcons.exe'
    condition: selection
falsepositives:
    - Dell Power Manager (C:\Program Files\Dell\PowerManager\DpmPowerPlanSetup.exe)
level: high
