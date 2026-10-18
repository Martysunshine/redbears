<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_event/registry_event_cmstp_execution_by_registry.yml -->
title: CMSTP Execution Registry Event
id: b6d235fc-1d38-4b12-adbe-325f06728f37
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
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains: '\cmmgr32.exe'
    condition: selection
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high
