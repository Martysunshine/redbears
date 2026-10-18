<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_webshell.yml -->
title: Remote Access Tool - ScreenConnect Server Web Shell Execution
id: b19146a3-25d4-41b4-928b-1e2a92641b1b
status: test
description: Detects potential web shell execution from the ScreenConnect server process.
references:
    - https://blackpointcyber.com/resources/blog/breaking-through-the-screen/
    - https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8
author: Jason Rathbun (Blackpoint Cyber)
date: 2024-02-26
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\ScreenConnect.Service.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\csc.exe'
    condition: selection
falsepositives:
    - Unlikely
level: high
