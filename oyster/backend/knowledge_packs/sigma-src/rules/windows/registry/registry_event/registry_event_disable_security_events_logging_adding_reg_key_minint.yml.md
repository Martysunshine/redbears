<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_event/registry_event_disable_security_events_logging_adding_reg_key_minint.yml -->
title: Disable Security Events Logging Adding Reg Key MiniNt
id: 919f2ef0-be2d-4a7a-b635-eb2b41fde044
status: test
description: Detects the addition of a key 'MiniNt' to the registry. Upon a reboot, Windows Event Log service will stop writing events.
references:
    - https://twitter.com/0gtweet/status/1182516740955226112
    - https://www.hackingarticles.in/defense-evasion-windows-event-logging-t1562-002/
author: Ilyas Ochkov, oscd.community
date: 2019-10-25
modified: 2021-11-27
tags:
    - attack.persistence
    - attack.defense-impairment
    - attack.t1685.001
    - attack.t1112
    - car.2022-03-001
logsource:
    category: registry_event
    product: windows
detection:
    selection:
    # Sysmon gives us HKLM\SYSTEM\CurrentControlSet\.. if ControlSetXX is the selected one
        - TargetObject: 'HKLM\SYSTEM\CurrentControlSet\Control\MiniNt'
          EventType: 'CreateKey'    # we don't want deletekey
    # key rename
        - NewName: 'HKLM\SYSTEM\CurrentControlSet\Control\MiniNt'
    condition: selection
falsepositives:
    - Unknown
level: high
