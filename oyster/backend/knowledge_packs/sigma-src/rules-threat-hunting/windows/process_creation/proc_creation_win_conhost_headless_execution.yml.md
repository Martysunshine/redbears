<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/process_creation/proc_creation_win_conhost_headless_execution.yml -->
title: Headless Process Launched Via Conhost.EXE
id: 00ca75ab-d5ce-43be-b86c-55ff39c6abfc
related:
    - id: 056c7317-9a09-4bd4-9067-d051312752ea
      type: derived
status: test
description: |
    Detects the launch of a child process via "conhost.exe" with the "--headless" flag.
    The "--headless" flag hides the windows from the user upon execution.
references:
    - https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-07-23
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1059.003
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\conhost.exe'
        ParentCommandLine|contains: '--headless'
    condition: selection
falsepositives:
    - Unknown
level: medium
