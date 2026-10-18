<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_speechruntime_child_process.yml -->
title: Suspicious Speech Runtime Binary Child Process
id: 78f10490-f2f4-4d19-a75b-4e0683bf3b8d
status: experimental
description: |
    Detects suspicious Speech Runtime Binary Execution by monitoring its child processes.
    Child processes spawned by SpeechRuntime.exe could indicate an attempt for lateral movement via COM & DCOM hijacking.
references:
    - https://github.com/rtecCyberSec/SpeechRuntimeMove
author: andrewdanis
date: 2025-10-23
logsource:
    category: process_creation
    product: windows
tags:
    - attack.lateral-movement
    - attack.stealth
    - attack.t1021.003
    - attack.t1218
detection:
    selection:
        ParentImage|endswith: '\SpeechRuntime.exe'
    condition: selection
falsepositives:
    - Unlikely.
level: high
