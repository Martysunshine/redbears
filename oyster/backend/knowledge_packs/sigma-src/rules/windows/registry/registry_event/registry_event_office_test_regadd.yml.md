<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_event/registry_event_office_test_regadd.yml -->
title: Office Application Startup - Office Test
id: 3d27f6dd-1c74-4687-b4fa-ca849d128d1c
status: test
description: Detects the addition of office test registry that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started
references:
    - https://unit42.paloaltonetworks.com/unit42-technical-walkthrough-office-test-persistence-method-used-in-recent-sofacy-attacks/
author: omkar72
date: 2020-10-25
modified: 2023-11-08
tags:
    - attack.persistence
    - attack.t1137.002
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Office test\Special\Perf'
    condition: selection
falsepositives:
    - Unlikely
level: medium
