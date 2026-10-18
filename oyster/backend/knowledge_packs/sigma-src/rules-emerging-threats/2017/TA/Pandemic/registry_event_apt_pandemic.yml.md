<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2017/TA/Pandemic/registry_event_apt_pandemic.yml -->
title: Pandemic Registry Key
id: 47e0852a-cf81-4494-a8e6-31864f8c86ed
status: test
description: Detects Pandemic Windows Implant
references:
    - https://wikileaks.org/vault7/#Pandemic
    - https://twitter.com/MalwareJake/status/870349480356454401
author: Florian Roth (Nextron Systems)
date: 2017-06-01
modified: 2022-10-09
tags:
    - attack.command-and-control
    - attack.t1105
    - detection.emerging-threats
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains: '\SYSTEM\CurrentControlSet\services\null\Instance'
    condition: selection
falsepositives:
    - Unknown
level: critical
