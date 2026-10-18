<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/process_creation/proc_creation_win_remote_access_tools_anyviewer_shell_exec.yml -->
title: Remote Access Tool - Cmd.EXE Execution via AnyViewer
id: bc533330-fc29-44c0-b245-7dc6e5939c87
status: test
description: |
    Detects execution of "cmd.exe" via the AnyViewer RMM agent on a remote management sessions.
references:
    - https://www.anyviewer.com/help/remote-technical-support.html
author: '@kostastsale'
date: 2024-08-03
tags:
    - attack.execution
    - attack.persistence
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\AVCore.exe'
        ParentCommandLine|contains: 'AVCore.exe" -d'
        Image|endswith: '\cmd.exe'
    condition: selection
falsepositives:
    - Legitimate use for admin activity.
level: medium
